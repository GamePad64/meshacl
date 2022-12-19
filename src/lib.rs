mod log;

use crate::log::AclRecordLog;
use crate::proto::AclRecord;
use libp2p_core::identity::Keypair;
use libp2p_core::{PeerId, PublicKey};
use multimap::MultiMap;
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;
use tracing::trace;

pub const ACL_CAPS_ROOT: &str = "acl.root";
pub const ACL_CAPS_CONTROLLER: &str = "meshlan.controller";

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/acl.rs"));
}

type KeyId = u32;
const KEY_ID_ROOT: KeyId = 0;

#[derive(ThisError, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AclError {
    #[error("ACL parse error")]
    ParseError,
    #[error("multiple roots found")]
    MultipleRoots,
    #[error("repeated grant found")]
    RepeatedGrant,
    #[error("trying to deny capability without a prior grant")]
    DenyingNotGranted,
    #[error("first record must be {ACL_CAPS_ROOT}")]
    FirstNotRoot,
}

#[derive(Default)]
pub struct InterpretedAcl {
    by_peer: MultiMap<PeerId, String>,
    log: AclRecordLog,

    keychain: Vec<PublicKey>,
}

impl InterpretedAcl {
    //     pub fn new(acl: &AclRecordLog) -> Result<Self, AclError> {
    //         let mut ret = InterpretedAcl::default();
    //         for record in &acl.records {
    //             ret.add(record)?;
    //         }
    //         Ok(ret)
    //     }
    //
    fn root(&self) -> Option<&PublicKey> {
        self.keychain.get(KEY_ID_ROOT as usize)
    }

    fn can_sign(key_id: KeyId) -> bool {
        todo!()
    }

    fn add(&mut self, record: &proto::SignedRecord) -> Result<(), AclError> {
        trace!("InterpretedAcl::add({record:?})");

        let plain_record = AclRecord::decode(record.record.as_slice()).unwrap();
        let mut signing_key = None;

        if self.root().is_none() && record.signer == KEY_ID_ROOT {
            if !plain_record.last.is_empty() {
                panic!()
            }
            let root_key = plain_record.keys.get(KEY_ID_ROOT as usize).unwrap();
            signing_key = Some(PublicKey::from_protobuf_encoding(root_key));
        }

        let mut keychain = self.keychain.clone();
        // for key in record.keys {
        //     keychain.push(PublicKey::from_protobuf_encoding(key.as_slice()).unwrap())
        // }

        todo!()
        //         match record.r#type {
        //             AclRecordType::Grant => {
        //                 if self.records.is_empty() && record.cap != ACL_CAPS_ROOT {
        //                     return Err(AclError::FirstNotRoot);
        //                 }
        //
        //                 if self.has_capability(&record.peer, &record.cap) {
        //                     return Err(AclError::RepeatedGrant);
        //                 }
        //
        //                 if record.cap == ACL_CAPS_ROOT {
        //                     if self.initial_root.is_none() {
        //                         self.initial_root = Some(record.peer);
        //                     } else {
        //                         return Err(AclError::MultipleRoots);
        //                     }
        //                 }
        //
        //                 self.by_peer.insert(record.peer, record.cap.clone());
        //             }
        //             AclRecordType::Deny => {
        //                 if let Some(caps) = self.by_peer.get_vec_mut(&record.peer) {
        //                     caps.retain(|cap| cap != &record.cap)
        //                 } else {
        //                     return Err(AclError::DenyingNotGranted);
        //                 }
        //             }
        //         }
        //         self.records.push(record.clone());
        //         Ok(())
    }
    //
    //     pub fn root(&self) -> PeerId {
    //         self.initial_root.unwrap()
    //     }
    //
    //     pub fn has_capability(&self, peer: &PeerId, capability: &str) -> bool {
    //         if let Some(caps) = self.by_peer.get_vec(peer) {
    //             return caps
    //                 .iter()
    //                 .any(|cap| cap == capability || cap == ACL_CAPS_ROOT);
    //         }
    //         false
    //     }
}
//
// #[cfg(test)]
// mod tests {
//     use super::{
//         AclError, AclRecord, AclRecordLog, AclRecordType, ACL_CAPS_CONTROLLER, ACL_CAPS_ROOT,
//     };
//     use libp2p_core::PeerId;
//
//     #[test]
//     fn test_ok() {
//         let peer_id = PeerId::random();
//         let mut acl = AclRecordLog::default();
//         acl.add(&[AclRecord {
//             r#type: AclRecordType::Grant,
//             cap: ACL_CAPS_ROOT.into(),
//             peer: peer_id,
//         }])
//         .unwrap();
//
//         assert!(acl.has_capability(&peer_id, ACL_CAPS_ROOT).unwrap());
//     }
//
//     #[test]
//     fn test_multiple_roots() {
//         let mut acl = AclRecordLog::default();
//         acl.add_root(PeerId::random()).unwrap();
//         assert_eq!(acl.add_root(PeerId::random()), Err(AclError::MultipleRoots));
//     }
//
//     #[test]
//     fn test_first_non_root() {
//         let mut acl = AclRecordLog::default();
//         assert_eq!(
//             acl.add(&[AclRecord {
//                 r#type: AclRecordType::Grant,
//                 cap: ACL_CAPS_CONTROLLER.into(),
//                 peer: PeerId::random()
//             }]),
//             Err(AclError::FirstNotRoot)
//         );
//     }
//
//     #[test]
//     fn test_typical_acl_start() {
//         let root = PeerId::random();
//         let controller = PeerId::random();
//
//         let mut acl = AclRecordLog::default();
//         acl.add_root(root).unwrap();
//         acl.add(&[AclRecord {
//             r#type: AclRecordType::Grant,
//             cap: ACL_CAPS_CONTROLLER.into(),
//             peer: controller,
//         }])
//         .unwrap();
//         acl.deny_root().unwrap();
//
//         // Root capability is dropped
//         assert!(!acl.has_capability(&root, ACL_CAPS_ROOT).unwrap());
//         assert!(acl
//             .has_capability(&controller, ACL_CAPS_CONTROLLER)
//             .unwrap());
//     }
//
//     #[test]
//     fn test_denying_not_granted() {
//         let mut acl = AclRecordLog::default();
//         assert_eq!(
//             acl.add(&[AclRecord {
//                 r#type: AclRecordType::Deny,
//                 cap: ACL_CAPS_CONTROLLER.into(),
//                 peer: PeerId::random(),
//             }]),
//             Err(AclError::DenyingNotGranted)
//         )
//     }
//
//     #[test]
//     fn test_repeated_grant() {
//         let mut acl = AclRecordLog::default();
//         acl.add_root(PeerId::random()).unwrap();
//         let controller = PeerId::random();
//
//         // 1st, ok
//         acl.add(&[AclRecord {
//             r#type: AclRecordType::Grant,
//             cap: ACL_CAPS_CONTROLLER.into(),
//             peer: controller,
//         }])
//         .unwrap();
//
//         // 2nd, not ok
//         assert_eq!(
//             acl.add(&[AclRecord {
//                 r#type: AclRecordType::Grant,
//                 cap: ACL_CAPS_CONTROLLER.into(),
//                 peer: controller,
//             }]),
//             Err(AclError::RepeatedGrant)
//         )
//     }
// }
