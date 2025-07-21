//! WOTS+ parameters and configuration

use serde::{Deserialize, Serialize};

/// WOTS+ parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WotsParams {
    /// Winternitz parameter (w = 2^log_w)
    pub log_w: u8,
    /// Hash output length in bytes
    pub n: u32,
    /// Private key length (derived from n and log_w)
    pub len: u32,
    /// Security parameter for addresses
    pub h: u32,
}

impl WotsParams {
    /// Create new WOTS parameters
    pub fn new(log_w: u8, n: u32, h: u32) -> Self {
        let len = Self::calculate_len(n, log_w);
        Self { log_w, n, len, h }
    }

    /// Calculate private key length based on parameters
    fn calculate_len(n: u32, log_w: u8) -> u32 {
        let _w = 1u32 << log_w;
        let len1 = (8 * n) / log_w as u32;
        let len2 = ((log_w as u32 * (len1 - 1)).ilog2() + 1 + log_w as u32 - 1) / log_w as u32;
        len1 + len2
    }

    /// Get Winternitz parameter w
    pub fn w(&self) -> u32 {
        1u32 << self.log_w
    }

    /// Get number of chains (len1)
    pub fn len1(&self) -> u32 {
        (8 * self.n) / self.log_w as u32
    }

    /// Get checksum chains (len2)
    pub fn len2(&self) -> u32 {
        self.len - self.len1()
    }

    /// Validate parameters
    pub fn is_valid(&self) -> bool {
        self.log_w > 0 && 
        self.log_w <= 8 && 
        self.n > 0 && 
        self.h > 0 &&
        self.len == Self::calculate_len(self.n, self.log_w)
    }
}

impl Default for WotsParams {
    /// Default WOTS+ parameters for Beam Chain
    /// Using w=16 (log_w=4), 32-byte hash, height 32
    fn default() -> Self {
        Self::new(4, 32, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        let params = WotsParams::default();
        assert_eq!(params.log_w, 4);
        assert_eq!(params.n, 32);
        assert_eq!(params.h, 32);
        assert_eq!(params.w(), 16);
        assert!(params.is_valid());
    }

    #[test]
    fn test_custom_params() {
        let params = WotsParams::new(3, 20, 16);
        assert_eq!(params.log_w, 3);
        assert_eq!(params.n, 20);
        assert_eq!(params.h, 16);
        assert_eq!(params.w(), 8);
        assert!(params.is_valid());
    }

    #[test]
    fn test_len_calculation() {
        let params = WotsParams::default();
        // For n=32, log_w=4: len1 = 64, len2 = 2, total = 66
        assert_eq!(params.len1(), 64);
        assert_eq!(params.len2(), 2);
        assert_eq!(params.len, 66);
    }
}
