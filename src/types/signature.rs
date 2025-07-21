// POAR Signature Types
// Digital signature implementation supporting Ed25519 and Falcon

use crate::types::{Hash, POARError, POARResult};
use crate::crypto::falcon::{FalconSignature, FalconSignatureManager, FalconConfig};
use crate::crypto::xmss::{XMSSSignature};
use crate::crypto::hash_based_multi_sig::AggregatedSignature;
use crate::crypto::signature::Ed25519SignatureBytes;
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey, Signer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash as StdHash;

pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureKind {
    Ed25519,
    Falcon,
    XMSS,
    AggregatedHashBasedMultiSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Ed25519(Ed25519SignatureBytes),
    Falcon(FalconSignature),
    XMSS(XMSSSignature),
    AggregatedHashBasedMultiSig(AggregatedSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Ed25519([u8; ED25519_PUBLIC_KEY_SIZE]),
    Falcon(Vec<u8>),
    XMSS(Vec<u8>),
    AggregatedHashBasedMultiSig(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateKey {
    Ed25519([u8; ED25519_PRIVATE_KEY_SIZE]),
    Falcon(Vec<u8>),
    XMSS(Vec<u8>),
    AggregatedHashBasedMultiSig(Vec<Vec<u8>>),
}

impl Signature {
    pub fn kind(&self) -> SignatureKind {
        match self {
            Signature::Ed25519(_) => SignatureKind::Ed25519,
            Signature::Falcon(_) => SignatureKind::Falcon,
            Signature::XMSS(_) => SignatureKind::XMSS,
            Signature::AggregatedHashBasedMultiSig(_) => SignatureKind::AggregatedHashBasedMultiSig,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(bytes) => bytes.to_vec(),
            Signature::Falcon(sig) => bincode::serialize(sig).unwrap_or_default(),
            Signature::XMSS(sig) => bincode::serialize(sig).unwrap_or_default(),
            Signature::AggregatedHashBasedMultiSig(sig) => bincode::serialize(sig).unwrap_or_default(),
        }
    }
    pub fn from_bytes(kind: SignatureKind, bytes: &[u8]) -> POARResult<Self> {
        match kind {
            SignatureKind::Ed25519 => {
                if bytes.len() != ED25519_SIGNATURE_SIZE {
                    return Err(POARError::CryptographicError(
                        format!("Invalid Ed25519 signature length: expected {}, got {}", ED25519_SIGNATURE_SIZE, bytes.len())
                    ));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(bytes);
                Ok(Signature::Ed25519(Ed25519SignatureBytes(arr)))
            }
            SignatureKind::Falcon => {
                let sig: FalconSignature = bincode::deserialize(bytes)
                    .map_err(|_| POARError::CryptographicError("Invalid Falcon signature bytes".to_string()))?;
                Ok(Signature::Falcon(sig))
            }
            SignatureKind::XMSS => {
                let sig: XMSSSignature = bincode::deserialize(bytes)
                    .map_err(|_| POARError::CryptographicError("Invalid XMSS signature bytes".to_string()))?;
                Ok(Signature::XMSS(sig))
            }
            SignatureKind::AggregatedHashBasedMultiSig => {
                let sig: AggregatedSignature = bincode::deserialize(bytes)
                    .map_err(|_| POARError::CryptographicError("Invalid AggregatedHashBasedMultiSig bytes".to_string()))?;
                Ok(Signature::AggregatedHashBasedMultiSig(sig))
            }
        }
    }
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> POARResult<bool> {
        match (self, public_key) {
            (Signature::Ed25519(bytes), PublicKey::Ed25519(pk_bytes)) => {
                let ed25519_sig = Ed25519Signature::from_bytes(&bytes.0);
                let ed25519_pk = VerifyingKey::from_bytes(pk_bytes)
                    .map_err(|e| POARError::CryptographicError(format!("Invalid public key: {}", e)))?;
                match ed25519_pk.verify_strict(message, &ed25519_sig) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            (Signature::Falcon(sig), PublicKey::Falcon(_pk_bytes)) => {
                let manager = FalconSignatureManager::new(FalconConfig::default());
                manager.verify(sig, message).map_err(|e| POARError::CryptographicError(e.to_string()))
            }
            (Signature::XMSS(sig), PublicKey::XMSS(_pk_bytes)) => {
                // TODO: Pass correct root and ots_public_keys here
                // Ok(sig.verify(message, root, ots_public_keys))
                unimplemented!("XMSS signature verification requires root and ots_public_keys")
            }
            (Signature::AggregatedHashBasedMultiSig(agg_sig), PublicKey::AggregatedHashBasedMultiSig(pk_list)) => {
                // TODO: Pass correct root and ots_public_keys here
                // Ok(crate::crypto::hash_based_multi_sig::verify_aggregated_signature(message, agg_sig, root, ots_public_keys, pk_list))
                unimplemented!("Aggregated signature verification requires root and ots_public_keys")
            }
            _ => Err(POARError::CryptographicError("Signature/PublicKey type mismatch".to_string())),
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature::Ed25519(crate::crypto::signature::Ed25519SignatureBytes([0u8; 64]))
    }
}

impl AsRef<[u8]> for crate::crypto::signature::Ed25519SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl crate::crypto::signature::Ed25519SignatureBytes {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PublicKey {
    pub fn from_bytes(kind: SignatureKind, bytes: &[u8]) -> POARResult<Self> {
        match kind {
            SignatureKind::Ed25519 => {
                if bytes.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(POARError::CryptographicError(
                        format!("Invalid Ed25519 public key length: expected {}, got {}", ED25519_PUBLIC_KEY_SIZE, bytes.len())
            ));
        }
                let mut arr = [0u8; ED25519_PUBLIC_KEY_SIZE];
                arr.copy_from_slice(bytes);
                Ok(PublicKey::Ed25519(arr))
            }
            SignatureKind::Falcon => Ok(PublicKey::Falcon(bytes.to_vec())),
            SignatureKind::XMSS => Ok(PublicKey::XMSS(bytes.to_vec())),
            SignatureKind::AggregatedHashBasedMultiSig => {
                // This case is not directly handled here, as AggregatedHashBasedMultiSig is a Vec<Vec<u8>>
                // and we need to deserialize the list of public keys.
                // This requires a more complex deserialization logic.
                // For now, we'll return an error as we don't have a direct deserialization method for this kind.
                Err(POARError::CryptographicError("AggregatedHashBasedMultiSig public key deserialization not implemented".to_string()))
            }
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(arr) => arr.to_vec(),
            PublicKey::Falcon(vec) => vec.clone(),
            PublicKey::XMSS(vec) => vec.clone(),
            PublicKey::AggregatedHashBasedMultiSig(pk_list) => {
                // This case is not directly handled here, as AggregatedHashBasedMultiSig is a Vec<Vec<u8>>
                // and we need to serialize the list of public keys.
                // This requires a more complex serialization logic.
                // For now, we'll return an empty vector as we don't have a direct serialization method for this kind.
                vec![]
            }
        }
    }
}

impl PrivateKey {
    pub fn from_bytes(kind: SignatureKind, bytes: &[u8]) -> POARResult<Self> {
        match kind {
            SignatureKind::Ed25519 => {
                if bytes.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(POARError::CryptographicError(
                        format!("Invalid Ed25519 private key length: expected {}, got {}", ED25519_PRIVATE_KEY_SIZE, bytes.len())
            ));
        }
                let mut arr = [0u8; ED25519_PRIVATE_KEY_SIZE];
                arr.copy_from_slice(bytes);
                Ok(PrivateKey::Ed25519(arr))
    }
            SignatureKind::Falcon => Ok(PrivateKey::Falcon(bytes.to_vec())),
            SignatureKind::XMSS => Ok(PrivateKey::XMSS(bytes.to_vec())),
            SignatureKind::AggregatedHashBasedMultiSig => {
                // This case is not directly handled here, as AggregatedHashBasedMultiSig is a Vec<Vec<u8>>
                // and we need to deserialize the list of private keys.
                // This requires a more complex deserialization logic.
                // For now, we'll return an error as we don't have a direct deserialization method for this kind.
                Err(POARError::CryptographicError("AggregatedHashBasedMultiSig private key deserialization not implemented".to_string()))
            }
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(arr) => arr.to_vec(),
            PrivateKey::Falcon(vec) => vec.clone(),
            PrivateKey::XMSS(vec) => vec.clone(),
            PrivateKey::AggregatedHashBasedMultiSig(_) => {
                // This case is not directly handled here, as AggregatedHashBasedMultiSig is a Vec<Vec<u8>>
                // and we need to serialize the list of private keys.
                // This requires a more complex serialization logic.
                // For now, we'll return an empty vector as we don't have a direct serialization method for this kind.
                vec![]
            }
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signature::Ed25519(bytes) => write!(f, "{}", hex::encode(bytes)),
            Signature::Falcon(sig) => write!(f, "Falcon({})", hex::encode(bincode::serialize(sig).unwrap_or_default())),
            Signature::XMSS(sig) => write!(f, "XMSS({})", hex::encode(bincode::serialize(sig).unwrap_or_default())),
            Signature::AggregatedHashBasedMultiSig(sig) => write!(f, "AggregatedHashBasedMultiSig({})", hex::encode(bincode::serialize(sig).unwrap_or_default())),
        }
    }
} 