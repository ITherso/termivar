use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::{sleep, Duration},
};
use url::Url;

use super::model::FIXTURE_RESPONSE_DELAY_MS;

const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1_024;
const FIXTURE_RESPONSE_DELAY: Duration = Duration::from_millis(FIXTURE_RESPONSE_DELAY_MS);

pub(super) struct LoopbackFixture {
    origin: Url,
    requests: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl LoopbackFixture {
    pub(super) async fn start(subjects: usize) -> Result<Self, String> {
        if subjects == 0 {
            return Err("fixture authority must expose at least one subject".to_owned());
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| format!("could not bind deterministic loopback fixture: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("could not inspect loopback fixture address: {error}"))?;
        if !address.ip().is_loopback() {
            return Err("fixture listener escaped loopback authority".to_owned());
        }

        let plan = Arc::new(FixtureAuthority::new(subjects));
        let requests = Arc::new(AtomicU64::new(0));
        let observed_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, peer)) = listener.accept().await else {
                    break;
                };
                if !peer.ip().is_loopback() {
                    let _ = stream.shutdown().await;
                    continue;
                }
                let response = match read_request_target(&mut stream).await {
                    Some(target) => {
                        observed_requests.fetch_add(1, Ordering::Relaxed);
                        response_for_target(&plan, &target)
                    },
                    None => not_found_response(),
                };
                sleep(FIXTURE_RESPONSE_DELAY).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        Ok(Self {
            origin: Url::parse(&format!("http://{address}/"))
                .map_err(|error| format!("could not form loopback fixture URL: {error}"))?,
            requests,
            task,
        })
    }

    pub(super) fn root(&self) -> Url {
        self.origin.clone()
    }

    pub(super) fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for LoopbackFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct FixtureAuthority {
    root_path: String,
    child_prefix: String,
    subjects: usize,
    root_body: Vec<u8>,
}

impl FixtureAuthority {
    fn new(subjects: usize) -> Self {
        let root_path = "/".to_owned();
        let child_prefix = "/endpoint-".to_owned();
        let mut root_body = String::from("<!doctype html><html><body>");
        for endpoint in 1..subjects {
            root_body.push_str(&format!(
                "<a href=\"{child_prefix}{endpoint:04}\">endpoint</a>"
            ));
        }
        root_body.push_str("</body></html>");
        Self {
            root_path,
            child_prefix,
            subjects,
            root_body: root_body.into_bytes(),
        }
    }

    fn body_for_path(&self, path: &str) -> Option<&[u8]> {
        if path == self.root_path {
            return Some(&self.root_body);
        }
        let suffix = path.strip_prefix(&self.child_prefix)?;
        if suffix.len() != 4 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let endpoint = suffix.parse::<usize>().ok()?;
        (endpoint > 0 && endpoint < self.subjects)
            .then_some(b"<!doctype html><html><body>fixture endpoint</body></html>".as_slice())
    }
}

async fn read_request_target(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut request = Vec::new();
    while request.len() < MAX_REQUEST_HEADER_BYTES {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    if request.len() >= MAX_REQUEST_HEADER_BYTES {
        return None;
    }
    let request = std::str::from_utf8(&request).ok()?;
    let mut request_line = request.lines().next()?.split_whitespace();
    if request_line.next()? != "GET" {
        return None;
    }
    let target = request_line.next()?;
    if !target.starts_with('/') || target.starts_with("//") {
        return None;
    }
    Some(target.split('?').next().unwrap_or(target).to_owned())
}

fn response_for_target(plan: &FixtureAuthority, target: &str) -> Vec<u8> {
    plan.body_for_path(target)
        .map_or_else(not_found_response, success_response)
}

fn success_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Security-Policy: default-src 'self'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Permissions-Policy: geolocation=()\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}
