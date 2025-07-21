use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

const WOTS_LEN: usize = 32; // 256 bit
const XMSS_TREE_HEIGHT: usize = 8; // 256 OTS anahtar

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XMSSKeyPair {
    pub ots_private_keys: Vec<[u8; WOTS_LEN]>,
    pub ots_public_keys: Vec<[u8; WOTS_LEN]>,
    pub merkle_tree: Vec<Vec<[u8; WOTS_LEN]>>, // Her seviye için hashler
    pub root: [u8; WOTS_LEN],
    pub next_unused: usize, // Sıradaki OTS anahtar
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XMSSSignature {
    pub ots_signature: [u8; WOTS_LEN],
    pub ots_index: usize,
    pub merkle_path: Vec<[u8; WOTS_LEN]>,
}

impl XMSSKeyPair {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut ots_private_keys = Vec::new();
        let mut ots_public_keys = Vec::new();
        for _ in 0..(1 << XMSS_TREE_HEIGHT) {
            let mut sk = [0u8; WOTS_LEN];
            rand::thread_rng().fill_bytes(&mut sk);
            let pk = Sha256::digest(&sk);
            ots_private_keys.push(sk);
            ots_public_keys.push(pk.into());
        }
        // Merkle ağacı oluştur
        let mut tree = vec![ots_public_keys.clone()];
        let mut current = ots_public_keys.clone();
        while current.len() > 1 {
            let mut next = Vec::new();
            for chunk in current.chunks(2) {
                let h = if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    hasher.finalize()
                } else {
                    Sha256::digest(&chunk[0])
                };
                next.push(h.into());
            }
            tree.push(next.clone());
            current = next;
        }
        let root = current[0];
        XMSSKeyPair {
            ots_private_keys,
            ots_public_keys,
            merkle_tree: tree,
            root,
            next_unused: 0,
        }
    }
    pub fn sign(&mut self, message: &[u8]) -> Option<XMSSSignature> {
        if self.next_unused >= self.ots_private_keys.len() {
            return None;
        }
        let sk = self.ots_private_keys[self.next_unused];
        let ots_signature = Sha256::digest([&sk, message].concat());
        let ots_index = self.next_unused;
        // Merkle path hesapla
        let mut path = Vec::new();
        let mut idx = ots_index;
        for level in 0..XMSS_TREE_HEIGHT {
            let sibling = if idx % 2 == 0 {
                idx + 1
            } else {
                idx - 1
            };
            if sibling < self.merkle_tree[level].len() {
                path.push(self.merkle_tree[level][sibling]);
            } else {
                path.push([0u8; WOTS_LEN]);
            }
            idx /= 2;
        }
        self.next_unused += 1;
        Some(XMSSSignature {
            ots_signature: ots_signature.into(),
            ots_index,
            merkle_path: path,
        })
    }
    pub fn public_key(&self) -> [u8; WOTS_LEN] {
        self.root
    }
}

impl XMSSSignature {
    pub fn verify(&self, message: &[u8], root: &[u8; WOTS_LEN], ots_public_keys: &[[u8; WOTS_LEN]]) -> bool {
        // OTS doğrulama (basit hash)
        let pk = Sha256::digest(&ots_public_keys[self.ots_index]);
        let sig = Sha256::digest([&ots_public_keys[self.ots_index], message].concat());
        if sig[..] != self.ots_signature[..] {
            return false;
        }
        // Merkle path ile root'a ulaş
        let mut hash = pk.into();
        let mut idx = self.ots_index;
        for (level, sibling_hash) in self.merkle_path.iter().enumerate() {
            let (left, right) = if idx % 2 == 0 {
                (hash, *sibling_hash)
            } else {
                (*sibling_hash, hash)
            };
            let mut hasher = Sha256::new();
            hasher.update(&left);
            hasher.update(&right);
            hash = hasher.finalize().into();
            idx /= 2;
        }
        &hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_xmss_sign_and_verify() {
        let mut kp = XMSSKeyPair::generate();
        let message = b"hello xmss!";
        let sig = kp.sign(message).unwrap();
        let valid = sig.verify(message, &kp.root, &kp.ots_public_keys);
        assert!(valid);
        // Yanlış mesaj
        let invalid = sig.verify(b"wrong", &kp.root, &kp.ots_public_keys);
        assert!(!invalid);
    }

    #[test]
    fn test_xmss_ots_reuse_fails() {
        let mut kp = XMSSKeyPair::generate();
        let message1 = b"msg1";
        let message2 = b"msg2";
        let sig1 = kp.sign(message1).unwrap();
        // Aynı OTS anahtarı tekrar kullanılmamalı
        let _ = kp.sign(message2).unwrap();
        // OTS index'i farklı olmalı
        assert_ne!(sig1.ots_index, kp.next_unused - 1);
    }

    #[test]
    fn test_xmss_merkle_path_validity() {
        let mut kp = XMSSKeyPair::generate();
        let message = b"merkle test";
        let sig = kp.sign(message).unwrap();
        // Merkle path uzunluğu doğru olmalı
        assert_eq!(sig.merkle_path.len(), XMSS_TREE_HEIGHT);
    }

    #[test]
    fn test_xmss_exhaustion() {
        let mut kp = XMSSKeyPair::generate();
        // Tüm OTS anahtarlarını kullan
        for _ in 0..(1 << XMSS_TREE_HEIGHT) {
            let _ = kp.sign(b"test");
        }
        // Fazladan imza isteği None dönmeli
        assert!(kp.sign(b"overflow").is_none());
    }
} 