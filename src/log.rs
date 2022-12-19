use crate::AclError;
use libp2p_core::identity::Keypair;
use libp2p_core::PublicKey;
use prost::Message;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/acl.rs"));
}
pub use proto::*;

type KeyId = u32;
const KEY_ID_ROOT: KeyId = 0;

impl AclPermission {
    fn grant(peers: &[KeyId], cap: String) -> Self {
        Self {
            r#type: AclRecordType::Grant as i32,
            cap,
            key_id: peers.to_vec(),
        }
    }

    fn deny(peers: &[KeyId], cap: String) -> Self {
        Self {
            r#type: AclRecordType::Deny as i32,
            cap,
            key_id: peers.to_vec(),
        }
    }
}

impl AclRecord {
    fn root(peer: &PublicKey) -> Self {
        Self {
            last: vec![],
            keys: vec![peer.to_protobuf_encoding()],
            permissions: vec![],
        }
    }

    fn from_last(last: &[u8]) -> Self {
        Self {
            last: last.to_vec(),
            keys: vec![],
            permissions: vec![],
        }
    }

    fn sign(self, key_id: KeyId, privkey: &Keypair) -> SignedRecord {
        let serialized = self.encode_to_vec();
        SignedRecord {
            signer: key_id,
            signature: privkey.sign(&serialized).unwrap(),
            record: serialized,
        }
    }
}

impl SignedRecord {
    fn root(root: &Keypair) -> Self {
        AclRecord::root(&root.public()).sign(0, root)
    }
}

impl TryFrom<String> for SignedRecord {
    type Error = AclError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let b64_decoded = base64::decode(value).map_err(|_| AclError::ParseError)?;
        Ok(proto::SignedRecord::decode(b64_decoded.as_ref()).map_err(|_| AclError::ParseError)?)
    }
}

impl From<SignedRecord> for String {
    fn from(value: SignedRecord) -> Self {
        base64::encode(value.encode_to_vec())
    }
}

#[derive(Clone, Default, Debug)]
pub struct AclRecordLog {
    records: Vec<SignedRecord>,
}

impl AclRecordLog {
    fn with_root(root: &Keypair) -> Self {
        let mut log = Self::default();
        log.extend(&[SignedRecord::root(&root)]);
        log
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn extend(&mut self, records: &[SignedRecord]) {
        self.records.extend_from_slice(records);
    }

    fn pop(&mut self) -> Option<SignedRecord> {
        self.records.pop()
    }

    fn can_advance_into(&self, advanced: &AclRecordLog) -> bool {
        advanced.records.starts_with(&self.records)
    }
}
