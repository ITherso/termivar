//! Deterministic, resource-bounded canonical tree hashing.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::{ApiVisibilityEvidenceError, ApiVisibilityLimits};
use super::{
    diff::{digest_path, fingerprint, PathDigest, PathFingerprint},
    policy::{
        ApiComparisonProfile, CURRENT_API_COMPARISON_ALGORITHM_VERSION,
        CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
    },
    ProfiledApiVisibilityError,
};

const RESOURCE_NODE_DOMAIN: &[u8] = b"venom.api-visibility.resource-node.v2\0";
const FIELD_NODE_DOMAIN: &[u8] = b"venom.api-visibility.field-node.v2\0";

pub(super) struct ProfiledCanonicalResult {
    pub(super) resource: [u8; 32],
    pub(super) fields: [u8; 32],
    pub(super) path_index: BTreeMap<PathDigest, PathFingerprint>,
}

pub(super) struct ProfiledCanonicalState<'a> {
    profile: &'a ApiComparisonProfile,
    limits: ApiVisibilityLimits,
    resource_written: u64,
    fields_written: u64,
    path_index: BTreeMap<PathDigest, PathFingerprint>,
}

impl<'a> ProfiledCanonicalState<'a> {
    pub(super) fn new(profile: &'a ApiComparisonProfile, limits: ApiVisibilityLimits) -> Self {
        Self {
            profile,
            limits,
            resource_written: 0,
            fields_written: 0,
            path_index: BTreeMap::new(),
        }
    }

    pub(super) fn capture(
        mut self,
        snapshot: &Value,
    ) -> Result<ProfiledCanonicalResult, ProfiledApiVisibilityError> {
        let mut actual_path = Vec::new();
        let mut structural_path = Vec::new();
        let root = self
            .visit(snapshot, &mut actual_path, &mut structural_path)?
            .unwrap_or(self.omitted_node()?);
        let resource = self.bind_root_signature(
            RESOURCE_NODE_DOMAIN,
            root.resource,
            ProfiledStream::Resources,
        )?;
        let fields =
            self.bind_root_signature(FIELD_NODE_DOMAIN, root.fields, ProfiledStream::Fields)?;
        Ok(ProfiledCanonicalResult {
            resource,
            fields,
            path_index: self.path_index,
        })
    }

    fn visit(
        &mut self,
        value: &Value,
        actual_path: &mut Vec<String>,
        structural_path: &mut Vec<String>,
    ) -> Result<Option<NodeDigests>, ProfiledApiVisibilityError> {
        if self.profile.is_ignored(actual_path) || !self.profile.is_relevant(actual_path) {
            return Ok(None);
        }

        let (type_mask, scalar_value_digest) = fingerprint(value);
        if !structural_path.is_empty() {
            let digest = digest_path(structural_path);
            self.path_index
                .entry(digest)
                .and_modify(|existing| {
                    existing.merge(PathFingerprint::new(type_mask, scalar_value_digest));
                })
                .or_insert_with(|| PathFingerprint::new(type_mask, scalar_value_digest));
        }

        let node = match value {
            Value::Null => self.scalar_node(b"null", b"null", None)?,
            Value::Bool(value) => self.scalar_node(
                b"bool",
                b"bool",
                Some(if *value { b"true" } else { b"false" }),
            )?,
            Value::Number(value) => {
                let rendered = value.to_string();
                let field_type = if value.is_i64() || value.is_u64() {
                    b"integer".as_slice()
                } else {
                    b"number".as_slice()
                };
                self.scalar_node(b"number", field_type, Some(rendered.as_bytes()))?
            },
            Value::String(value) => {
                self.scalar_node(b"string", b"string", Some(value.as_bytes()))?
            },
            Value::Array(values) => {
                let mut children = Vec::new();
                for (index, value) in values.iter().enumerate() {
                    actual_path.push(index.to_string());
                    structural_path.push("*".to_owned());
                    if let Some(child) = self.visit(value, actual_path, structural_path)? {
                        children.push(child);
                    }
                    structural_path.pop();
                    actual_path.pop();
                }
                self.array_node(children, self.profile.is_unordered_array(actual_path))?
            },
            Value::Object(values) => {
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
                let mut children = Vec::new();
                for (key, value) in entries {
                    actual_path.push(key.clone());
                    structural_path.push(key.clone());
                    if let Some(child) = self.visit(value, actual_path, structural_path)? {
                        children.push((key.as_bytes(), child));
                    }
                    structural_path.pop();
                    actual_path.pop();
                }
                self.object_node(children)?
            },
        };
        Ok(Some(node))
    }

    fn omitted_node(&mut self) -> Result<NodeDigests, ProfiledApiVisibilityError> {
        self.scalar_node(b"omitted", b"omitted", None)
    }

    fn scalar_node(
        &mut self,
        resource_type: &[u8],
        field_type: &[u8],
        value: Option<&[u8]>,
    ) -> Result<NodeDigests, ProfiledApiVisibilityError> {
        let mut resource = Sha256::new();
        resource.update(RESOURCE_NODE_DOMAIN);
        write_profiled(
            &mut resource,
            resource_type,
            &mut self.resource_written,
            self.limits,
            "profiled-resources",
        )?;
        if let Some(value) = value {
            write_profiled_len(
                &mut resource,
                value.len(),
                &mut self.resource_written,
                self.limits,
                "profiled-resources",
            )?;
            write_profiled(
                &mut resource,
                value,
                &mut self.resource_written,
                self.limits,
                "profiled-resources",
            )?;
        }

        let mut fields = Sha256::new();
        fields.update(FIELD_NODE_DOMAIN);
        write_profiled(
            &mut fields,
            field_type,
            &mut self.fields_written,
            self.limits,
            "profiled-fields",
        )?;
        Ok(NodeDigests {
            resource: resource.finalize().into(),
            fields: fields.finalize().into(),
        })
    }

    fn array_node(
        &mut self,
        mut children: Vec<NodeDigests>,
        unordered: bool,
    ) -> Result<NodeDigests, ProfiledApiVisibilityError> {
        let mut resource_children = children
            .iter()
            .map(|child| child.resource)
            .collect::<Vec<_>>();
        let mut field_children = children
            .drain(..)
            .map(|child| child.fields)
            .collect::<Vec<_>>();
        if unordered {
            resource_children.sort_unstable();
            field_children.sort_unstable();
        }

        let order_tag: &[u8] = if unordered { b"unordered" } else { b"ordered" };
        let resource = self.container_hash(
            RESOURCE_NODE_DOMAIN,
            b"array",
            order_tag,
            &resource_children,
            ProfiledStream::Resources,
        )?;
        let fields = self.container_hash(
            FIELD_NODE_DOMAIN,
            b"array",
            order_tag,
            &field_children,
            ProfiledStream::Fields,
        )?;
        Ok(NodeDigests { resource, fields })
    }

    fn object_node(
        &mut self,
        children: Vec<(&[u8], NodeDigests)>,
    ) -> Result<NodeDigests, ProfiledApiVisibilityError> {
        let mut resource = Sha256::new();
        resource.update(RESOURCE_NODE_DOMAIN);
        self.write_stream(&mut resource, b"object", ProfiledStream::Resources)?;
        self.write_stream_len(&mut resource, children.len(), ProfiledStream::Resources)?;

        let mut fields = Sha256::new();
        fields.update(FIELD_NODE_DOMAIN);
        self.write_stream(&mut fields, b"object", ProfiledStream::Fields)?;
        self.write_stream_len(&mut fields, children.len(), ProfiledStream::Fields)?;

        for (key, child) in children {
            self.write_stream_len(&mut resource, key.len(), ProfiledStream::Resources)?;
            self.write_stream(&mut resource, key, ProfiledStream::Resources)?;
            self.write_stream(&mut resource, &child.resource, ProfiledStream::Resources)?;

            self.write_stream_len(&mut fields, key.len(), ProfiledStream::Fields)?;
            self.write_stream(&mut fields, key, ProfiledStream::Fields)?;
            self.write_stream(&mut fields, &child.fields, ProfiledStream::Fields)?;
        }
        Ok(NodeDigests {
            resource: resource.finalize().into(),
            fields: fields.finalize().into(),
        })
    }

    fn container_hash(
        &mut self,
        domain: &[u8],
        container_type: &[u8],
        order_tag: &[u8],
        children: &[[u8; 32]],
        stream: ProfiledStream,
    ) -> Result<[u8; 32], ProfiledApiVisibilityError> {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        self.write_stream(&mut hasher, container_type, stream)?;
        self.write_stream(&mut hasher, order_tag, stream)?;
        self.write_stream_len(&mut hasher, children.len(), stream)?;
        for child in children {
            self.write_stream(&mut hasher, child, stream)?;
        }
        Ok(hasher.finalize().into())
    }

    fn bind_root_signature(
        &mut self,
        domain: &[u8],
        root: [u8; 32],
        stream: ProfiledStream,
    ) -> Result<[u8; 32], ProfiledApiVisibilityError> {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        self.write_stream(
            &mut hasher,
            CURRENT_API_COMPARISON_ALGORITHM_VERSION.as_str().as_bytes(),
            stream,
        )?;
        self.write_stream(
            &mut hasher,
            CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION
                .as_str()
                .as_bytes(),
            stream,
        )?;
        self.write_stream(
            &mut hasher,
            self.profile.projection_policy_id().as_bytes(),
            stream,
        )?;
        self.write_stream(&mut hasher, &root, stream)?;
        Ok(hasher.finalize().into())
    }

    fn write_stream(
        &mut self,
        hasher: &mut Sha256,
        bytes: &[u8],
        stream: ProfiledStream,
    ) -> Result<(), ProfiledApiVisibilityError> {
        let (written, name) = match stream {
            ProfiledStream::Resources => (&mut self.resource_written, "profiled-resources"),
            ProfiledStream::Fields => (&mut self.fields_written, "profiled-fields"),
        };
        write_profiled(hasher, bytes, written, self.limits, name)
    }

    fn write_stream_len(
        &mut self,
        hasher: &mut Sha256,
        length: usize,
        stream: ProfiledStream,
    ) -> Result<(), ProfiledApiVisibilityError> {
        self.write_stream(
            hasher,
            &u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes(),
            stream,
        )
    }
}

#[derive(Clone, Copy)]
struct NodeDigests {
    resource: [u8; 32],
    fields: [u8; 32],
}

#[derive(Clone, Copy)]
enum ProfiledStream {
    Resources,
    Fields,
}

fn write_profiled(
    hasher: &mut Sha256,
    bytes: &[u8],
    written: &mut u64,
    limits: ApiVisibilityLimits,
    stream: &'static str,
) -> Result<(), ProfiledApiVisibilityError> {
    let observed = written.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    if observed > limits.max_canonical_bytes() {
        return Err(ApiVisibilityEvidenceError::CanonicalBytesLimitExceeded {
            signature: stream,
            limit: limits.max_canonical_bytes(),
            observed,
        }
        .into());
    }
    hasher.update(bytes);
    *written = observed;
    Ok(())
}

fn write_profiled_len(
    hasher: &mut Sha256,
    length: usize,
    written: &mut u64,
    limits: ApiVisibilityLimits,
    stream: &'static str,
) -> Result<(), ProfiledApiVisibilityError> {
    write_profiled(
        hasher,
        &u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes(),
        written,
        limits,
        stream,
    )
}
