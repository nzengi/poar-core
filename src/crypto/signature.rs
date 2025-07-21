// POAR signature module - Falcon & Ed25519 support

use crate::crypto::falcon::{FalconSignature, FalconSignatureManager, FalconConfig};
use crate::types::{POARError, POARResult};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureKind {
    Ed25519,
    Falcon,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Signature {
    Ed25519([u8; 64]),
    Falcon(FalconSignature),
}

impl Signature {
    pub fn sign_ed25519(message: &[u8], private_key: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(private_key);
        let signature = signing_key.sign(message);
        Signature::Ed25519(signature.to_bytes())
    }

    pub fn sign_falcon(message: &[u8], private_key: &[u8]) -> POARResult<Self> {
        let manager = FalconSignatureManager::new(FalconConfig::default());
        let sig = manager.sign(message, private_key)?;
        Ok(Signature::Falcon(sig))
    }

    pub fn verify(&self, message: &[u8], public_key: &[u8]) -> POARResult<bool> {
        match self {
            Signature::Ed25519(bytes) => {
                let ed25519_sig = Ed25519Signature::from_bytes(bytes);
                let ed25519_pk = VerifyingKey::from_bytes(public_key)
                    .map_err(|e| POARError::CryptographicError(format!("Invalid public key: {}", e)))?;
                match ed25519_pk.verify_strict(message, &ed25519_sig) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Signature::Falcon(sig) => {
                let manager = FalconSignatureManager::new(FalconConfig::default());
                manager.verify(sig, message)
            }
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self {
            Signature::Ed25519(_) => SignatureKind::Ed25519,
            Signature::Falcon(_) => SignatureKind::Falcon,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(bytes) => bytes.to_vec(),
            Signature::Falcon(sig) => bincode::serialize(sig).unwrap_or_default(),
        }
    }

    pub fn from_bytes(kind: SignatureKind, bytes: &[u8]) -> POARResult<Self> {
        match kind {
            SignatureKind::Ed25519 => {
                if bytes.len() != 64 {
                    return Err(POARError::CryptographicError("Invalid Ed25519 signature length".to_string()));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(bytes);
                Ok(Signature::Ed25519(arr))
            }
            SignatureKind::Falcon => {
                let sig: FalconSignature = bincode::deserialize(bytes)
                    .map_err(|_| POARError::CryptographicError("Invalid Falcon signature bytes".to_string()))?;
                Ok(Signature::Falcon(sig))
            }
        }
    }
}
