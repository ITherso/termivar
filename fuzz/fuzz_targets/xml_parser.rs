#![no_main]

use libfuzzer_sys::fuzz_target;
use quick_xml::events::Event;

fuzz_target!(|data: &[u8]| {
    let mut reader = quick_xml::Reader::from_reader(data);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => buffer.clear(),
        }
    }
});
