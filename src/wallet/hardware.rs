//! POAR Wallet Hardware Wallet Manager
//! 
//! This module provides hardware wallet support for POAR wallet with:
//! - Ledger Nano S/X support
//! - Trezor Model T support
//! - Generic HID device support
//! - Secure key derivation
//! - Transaction signing
//! - Device management

use crate::types::{Address, Signature, Hash, Transaction};
use crate::types::signature::SignatureKind;
use crate::types::transaction::TransactionType;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hardware wallet types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HardwareWalletType {
    LedgerNanoS,
    LedgerNanoX,
    TrezorModelT,
    TrezorOne,
    GenericHID,
    Unknown,
}

/// Hardware wallet connection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connected,
    Locked,
    Unlocked,
    Error { message: String },
}

/// Hardware wallet device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareDevice {
    pub device_id: String,
    pub device_type: HardwareWalletType,
    pub name: String,
    pub firmware_version: String,
    pub connection_status: ConnectionStatus,
    pub connected_at: Option<u64>,
    pub last_used: Option<u64>,
    pub supported_features: Vec<HardwareFeature>,
    pub derivation_paths: Vec<String>,
}

/// Hardware wallet features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HardwareFeature {
    Ed25519Signing,
    FalconSigning,
    XMSSSigning,
    MultiSigSupport,
    SecureElement,
    PassphraseSupport,
    U2FSupport,
    GPGSupport,
}

/// Hardware wallet errors
#[derive(Debug)]
pub enum HardwareWalletError {
    DeviceNotFound(String),
    ConnectionFailed(String),
    CommunicationError(String),
    SigningError(String),
    InvalidDerivationPath(String),
    DeviceLocked(String),
    Timeout(String),
    UnsupportedFeature(String),
    InvalidResponse(String),
    Unknown(String),
}

impl fmt::Display for HardwareWalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardwareWalletError::DeviceNotFound(msg) => write!(f, "Device not found: {}", msg),
            HardwareWalletError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            HardwareWalletError::CommunicationError(msg) => write!(f, "Communication error: {}", msg),
            HardwareWalletError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            HardwareWalletError::InvalidDerivationPath(msg) => write!(f, "Invalid derivation path: {}", msg),
            HardwareWalletError::DeviceLocked(msg) => write!(f, "Device locked: {}", msg),
            HardwareWalletError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            HardwareWalletError::UnsupportedFeature(msg) => write!(f, "Unsupported feature: {}", msg),
            HardwareWalletError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            HardwareWalletError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for HardwareWalletError {}

/// Hardware wallet manager
pub struct HardwareWalletManager {
    /// Connected devices
    connected_devices: Arc<Mutex<HashMap<String, HardwareDevice>>>,
    /// Device drivers
    device_drivers: HashMap<HardwareWalletType, Box<dyn HardwareDriver>>,
    /// Configuration
    config: HardwareWalletConfig,
}

/// Hardware wallet driver trait
pub trait HardwareDriver: Send + Sync {
    fn connect(&mut self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError>;
    fn disconnect(&mut self, device_id: &str) -> Result<(), HardwareWalletError>;
    fn get_device_info(&self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError>;
    fn sign_transaction(&self, device_id: &str, transaction: &Transaction, path: &str) -> Result<Signature, HardwareWalletError>;
    fn sign_message(&self, device_id: &str, message: &[u8], path: &str) -> Result<Signature, HardwareWalletError>;
    fn get_public_key(&self, device_id: &str, path: &str) -> Result<Vec<u8>, HardwareWalletError>;
    fn verify_pin(&self, device_id: &str, pin: &str) -> Result<bool, HardwareWalletError>;
    fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<(), HardwareWalletError>;
    fn is_connected(&self, device_id: &str) -> bool;
}

/// Hardware wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletConfig {
    pub auto_discover: bool,
    pub connection_timeout: Duration,
    pub signing_timeout: Duration,
    pub max_retries: u32,
    pub supported_devices: Vec<HardwareWalletType>,
    pub default_derivation_path: String,
    pub enable_passphrase: bool,
    pub enable_u2f: bool,
}

/// Ledger driver implementation
pub struct LedgerDriver {
    devices: HashMap<String, HardwareDevice>,
}

/// Trezor driver implementation
pub struct TrezorDriver {
    devices: HashMap<String, HardwareDevice>,
}

/// Generic HID driver implementation
pub struct GenericHIDDriver {
    devices: HashMap<String, HardwareDevice>,
}

impl HardwareWalletManager {
    /// Create new hardware wallet manager
    pub fn new() -> Self {
        let mut device_drivers: HashMap<HardwareWalletType, Box<dyn HardwareDriver>> = HashMap::new();
        
        // Register device drivers
        device_drivers.insert(HardwareWalletType::LedgerNanoS, Box::new(LedgerDriver::new()));
        device_drivers.insert(HardwareWalletType::LedgerNanoX, Box::new(LedgerDriver::new()));
        device_drivers.insert(HardwareWalletType::TrezorModelT, Box::new(TrezorDriver::new()));
        device_drivers.insert(HardwareWalletType::TrezorOne, Box::new(TrezorDriver::new()));
        device_drivers.insert(HardwareWalletType::GenericHID, Box::new(GenericHIDDriver::new()));

        let config = HardwareWalletConfig {
            auto_discover: true,
            connection_timeout: Duration::from_secs(10),
            signing_timeout: Duration::from_secs(30),
            max_retries: 3,
            supported_devices: vec![
                HardwareWalletType::LedgerNanoS,
                HardwareWalletType::LedgerNanoX,
                HardwareWalletType::TrezorModelT,
                HardwareWalletType::TrezorOne,
                HardwareWalletType::GenericHID,
            ],
            default_derivation_path: "m/44'/1234'/0'/0/0".to_string(),
            enable_passphrase: true,
            enable_u2f: true,
        };

        Self {
            connected_devices: Arc::new(Mutex::new(HashMap::new())),
            device_drivers,
            config,
        }
    }

    /// Discover and connect to hardware wallets
    pub fn discover_devices(&mut self) -> Result<Vec<HardwareDevice>, HardwareWalletError> {
        let mut discovered_devices = Vec::new();

        for device_type in &self.config.supported_devices {
            // Simulate device scanning for each supported device type
            let devices = match device_type {
                HardwareWalletType::LedgerNanoS | HardwareWalletType::LedgerNanoX => {
                    let device = HardwareDevice {
                        device_id: format!("ledger_{:?}", device_type),
                        device_type: device_type.clone(),
                        name: format!("{:?}", device_type),
                        firmware_version: "2.1.0".to_string(),
                        connection_status: ConnectionStatus::Disconnected,
                        connected_at: None,
                        last_used: None,
                        supported_features: vec![
                            HardwareFeature::Ed25519Signing,
                            HardwareFeature::SecureElement,
                            HardwareFeature::PassphraseSupport,
                        ],
                        derivation_paths: vec![
                            "m/44'/1234'/0'/0/0".to_string(),
                            "m/44'/1234'/0'/0/1".to_string(),
                        ],
                    };
                    vec![device]
                }
                HardwareWalletType::TrezorModelT | HardwareWalletType::TrezorOne => {
                    let device = HardwareDevice {
                        device_id: format!("trezor_{:?}", device_type),
                        device_type: device_type.clone(),
                        name: format!("{:?}", device_type),
                        firmware_version: "2.5.0".to_string(),
                        connection_status: ConnectionStatus::Disconnected,
                        connected_at: None,
                        last_used: None,
                        supported_features: vec![
                            HardwareFeature::Ed25519Signing,
                            HardwareFeature::FalconSigning,
                            HardwareFeature::MultiSigSupport,
                            HardwareFeature::PassphraseSupport,
                        ],
                        derivation_paths: vec![
                            "m/44'/1234'/0'/0/0".to_string(),
                            "m/44'/1234'/0'/0/1".to_string(),
                        ],
                    };
                    vec![device]
                }
                _ => {
                    let device = HardwareDevice {
                        device_id: format!("generic_{:?}", device_type),
                        device_type: device_type.clone(),
                        name: format!("{:?}", device_type),
                        firmware_version: "1.0.0".to_string(),
                        connection_status: ConnectionStatus::Disconnected,
                        connected_at: None,
                        last_used: None,
                        supported_features: vec![
                            HardwareFeature::Ed25519Signing,
                        ],
                        derivation_paths: vec![
                            "m/44'/1234'/0'/0/0".to_string(),
                        ],
                    };
                    vec![device]
                }
            };
            discovered_devices.extend(devices);
        }

        Ok(discovered_devices)
    }

    /// Connect to a specific hardware wallet
    pub fn connect_device(&mut self, device_id: &str, device_type: HardwareWalletType) -> Result<(), HardwareWalletError> {
        if let Some(driver) = self.device_drivers.get_mut(&device_type) {
            let device = driver.connect(device_id)?;
            
            let mut devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            devices.insert(device_id.to_string(), device);
        } else {
            return Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)));
        }

        Ok(())
    }

    /// Disconnect from a hardware wallet
    pub fn disconnect_device(&mut self, device_id: &str) -> Result<(), HardwareWalletError> {
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get_mut(&device_type) {
            driver.disconnect(device_id)?;
            
            let mut devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            devices.remove(device_id);
        }

        Ok(())
    }

    /// Sign a transaction with hardware wallet
    pub fn sign_transaction(
        &self,
        device_id: &str,
        transaction: &Transaction,
        derivation_path: Option<&str>,
    ) -> Result<Signature, HardwareWalletError> {
        let path = derivation_path.unwrap_or(&self.config.default_derivation_path);
        
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get(&device_type) {
            let signature = driver.sign_transaction(device_id, transaction, path)?;
            
            // Update last used timestamp
            {
                let mut devices = self.connected_devices.lock()
                    .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
                if let Some(device) = devices.get_mut(device_id) {
                    device.last_used = Some(Self::current_timestamp());
                }
            }

            Ok(signature)
        } else {
            Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)))
        }
    }

    /// Sign a message with hardware wallet
    pub fn sign_message(
        &self,
        device_id: &str,
        message: &[u8],
        derivation_path: Option<&str>,
    ) -> Result<Signature, HardwareWalletError> {
        let path = derivation_path.unwrap_or(&self.config.default_derivation_path);
        
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get(&device_type) {
            let signature = driver.sign_message(device_id, message, path)?;
            
            // Update last used timestamp
            {
                let mut devices = self.connected_devices.lock()
                    .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
                if let Some(device) = devices.get_mut(device_id) {
                    device.last_used = Some(Self::current_timestamp());
                }
            }

            Ok(signature)
        } else {
            Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)))
        }
    }

    /// Get public key from hardware wallet
    pub fn get_public_key(
        &self,
        device_id: &str,
        derivation_path: Option<&str>,
    ) -> Result<Vec<u8>, HardwareWalletError> {
        let path = derivation_path.unwrap_or(&self.config.default_derivation_path);
        
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get(&device_type) {
            driver.get_public_key(device_id, path)
        } else {
            Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)))
        }
    }

    /// Get connected devices
    pub fn get_connected_devices(&self) -> Result<Vec<HardwareDevice>, HardwareWalletError> {
        let devices = self.connected_devices.lock()
            .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
        
        Ok(devices.values().cloned().collect())
    }

    /// Get device info
    pub fn get_device_info(&self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        let devices = self.connected_devices.lock()
            .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
        
        devices.get(device_id)
            .cloned()
            .ok_or_else(|| HardwareWalletError::DeviceNotFound(device_id.to_string()))
    }

    /// Verify PIN
    pub fn verify_pin(&self, device_id: &str, pin: &str) -> Result<bool, HardwareWalletError> {
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get(&device_type) {
            driver.verify_pin(device_id, pin)
        } else {
            Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)))
        }
    }

    /// Change PIN
    pub fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<(), HardwareWalletError> {
        let device_type = {
            let devices = self.connected_devices.lock()
                .map_err(|e| HardwareWalletError::Unknown(e.to_string()))?;
            
            if let Some(device) = devices.get(device_id) {
                device.device_type.clone()
            } else {
                return Err(HardwareWalletError::DeviceNotFound(device_id.to_string()));
            }
        };

        if let Some(driver) = self.device_drivers.get(&device_type) {
            driver.change_pin(device_id, old_pin, new_pin)
        } else {
            Err(HardwareWalletError::UnsupportedFeature(format!("Device type {:?} not supported", device_type)))
        }
    }

    // Private helper methods

    fn scan_for_devices(
        &self,
        driver: &mut Box<dyn HardwareDriver>,
        device_type: &HardwareWalletType,
    ) -> Result<Vec<HardwareDevice>, HardwareWalletError> {
        // Simulate device scanning
        // In production, this would use HID or USB APIs
        let mut devices = Vec::new();
        
        match device_type {
            HardwareWalletType::LedgerNanoS | HardwareWalletType::LedgerNanoX => {
                // Simulate finding Ledger devices
                let device = HardwareDevice {
                    device_id: format!("ledger_{:?}", device_type),
                    device_type: device_type.clone(),
                    name: format!("{:?}", device_type),
                    firmware_version: "2.1.0".to_string(),
                    connection_status: ConnectionStatus::Disconnected,
                    connected_at: None,
                    last_used: None,
                    supported_features: vec![
                        HardwareFeature::Ed25519Signing,
                        HardwareFeature::SecureElement,
                        HardwareFeature::PassphraseSupport,
                    ],
                    derivation_paths: vec![
                        "m/44'/1234'/0'/0/0".to_string(),
                        "m/44'/1234'/0'/0/1".to_string(),
                    ],
                };
                devices.push(device);
            }
            HardwareWalletType::TrezorModelT | HardwareWalletType::TrezorOne => {
                // Simulate finding Trezor devices
                let device = HardwareDevice {
                    device_id: format!("trezor_{:?}", device_type),
                    device_type: device_type.clone(),
                    name: format!("{:?}", device_type),
                    firmware_version: "2.5.0".to_string(),
                    connection_status: ConnectionStatus::Disconnected,
                    connected_at: None,
                    last_used: None,
                    supported_features: vec![
                        HardwareFeature::Ed25519Signing,
                        HardwareFeature::FalconSigning,
                        HardwareFeature::MultiSigSupport,
                        HardwareFeature::PassphraseSupport,
                    ],
                    derivation_paths: vec![
                        "m/44'/1234'/0'/0/0".to_string(),
                        "m/44'/1234'/0'/0/1".to_string(),
                    ],
                };
                devices.push(device);
            }
            _ => {
                // Generic HID device
                let device = HardwareDevice {
                    device_id: format!("generic_{:?}", device_type),
                    device_type: device_type.clone(),
                    name: format!("{:?}", device_type),
                    firmware_version: "1.0.0".to_string(),
                    connection_status: ConnectionStatus::Disconnected,
                    connected_at: None,
                    last_used: None,
                    supported_features: vec![
                        HardwareFeature::Ed25519Signing,
                    ],
                    derivation_paths: vec![
                        "m/44'/1234'/0'/0/0".to_string(),
                    ],
                };
                devices.push(device);
            }
        }

        Ok(devices)
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl LedgerDriver {
    fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }
}

impl HardwareDriver for LedgerDriver {
    fn connect(&mut self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        // Simulate Ledger connection
        let device = HardwareDevice {
            device_id: device_id.to_string(),
            device_type: HardwareWalletType::LedgerNanoS,
            name: "Ledger Nano S".to_string(),
            firmware_version: "2.1.0".to_string(),
            connection_status: ConnectionStatus::Connected,
            connected_at: Some(Self::current_timestamp()),
            last_used: None,
            supported_features: vec![
                HardwareFeature::Ed25519Signing,
                HardwareFeature::SecureElement,
                HardwareFeature::PassphraseSupport,
            ],
            derivation_paths: vec![
                "m/44'/1234'/0'/0/0".to_string(),
                "m/44'/1234'/0'/0/1".to_string(),
            ],
        };
        
        self.devices.insert(device_id.to_string(), device.clone());
        Ok(device)
    }

    fn disconnect(&mut self, device_id: &str) -> Result<(), HardwareWalletError> {
        self.devices.remove(device_id);
        Ok(())
    }

    fn get_device_info(&self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        self.devices.get(device_id)
            .cloned()
            .ok_or_else(|| HardwareWalletError::DeviceNotFound(device_id.to_string()))
    }

    fn sign_transaction(&self, device_id: &str, transaction: &Transaction, path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate Ledger transaction signing
        println!("Ledger signing transaction: {} with path: {}", transaction.hash, path);
        
        // In production, this would send APDU commands to the Ledger
        let signature_data = format!("{}:{}", transaction.hash, path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature (in production, this would be the actual signature from Ledger)
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn sign_message(&self, device_id: &str, message: &[u8], path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate Ledger message signing
        println!("Ledger signing message with path: {}", path);
        
        // In production, this would send APDU commands to the Ledger
        let signature_data = format!("{}:{}", hex::encode(message), path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn get_public_key(&self, device_id: &str, path: &str) -> Result<Vec<u8>, HardwareWalletError> {
        // Simulate getting public key from Ledger
        println!("Ledger getting public key for path: {}", path);
        
        // In production, this would send APDU commands to the Ledger
        let public_key = format!("ledger_public_key_{}", path);
        Ok(public_key.as_bytes().to_vec())
    }

    fn verify_pin(&self, device_id: &str, pin: &str) -> Result<bool, HardwareWalletError> {
        // Simulate PIN verification
        Ok(pin == "1234")
    }

    fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<(), HardwareWalletError> {
        // Simulate PIN change
        if old_pin == "1234" {
            println!("Ledger PIN changed from {} to {}", old_pin, new_pin);
            Ok(())
        } else {
            Err(HardwareWalletError::InvalidResponse("Invalid old PIN".to_string()))
        }
    }

    fn is_connected(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }
}

impl TrezorDriver {
    fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }
}

impl HardwareDriver for TrezorDriver {
    fn connect(&mut self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        // Simulate Trezor connection
        let device = HardwareDevice {
            device_id: device_id.to_string(),
            device_type: HardwareWalletType::TrezorModelT,
            name: "Trezor Model T".to_string(),
            firmware_version: "2.5.0".to_string(),
            connection_status: ConnectionStatus::Connected,
            connected_at: Some(Self::current_timestamp()),
            last_used: None,
            supported_features: vec![
                HardwareFeature::Ed25519Signing,
                HardwareFeature::FalconSigning,
                HardwareFeature::MultiSigSupport,
                HardwareFeature::PassphraseSupport,
            ],
            derivation_paths: vec![
                "m/44'/1234'/0'/0/0".to_string(),
                "m/44'/1234'/0'/0/1".to_string(),
            ],
        };
        
        self.devices.insert(device_id.to_string(), device.clone());
        Ok(device)
    }

    fn disconnect(&mut self, device_id: &str) -> Result<(), HardwareWalletError> {
        self.devices.remove(device_id);
        Ok(())
    }

    fn get_device_info(&self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        self.devices.get(device_id)
            .cloned()
            .ok_or_else(|| HardwareWalletError::DeviceNotFound(device_id.to_string()))
    }

    fn sign_transaction(&self, device_id: &str, transaction: &Transaction, path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate Trezor transaction signing
        println!("Trezor signing transaction: {} with path: {}", transaction.hash, path);
        
        // In production, this would use Trezor's protocol
        let signature_data = format!("{}:{}", transaction.hash, path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn sign_message(&self, device_id: &str, message: &[u8], path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate Trezor message signing
        println!("Trezor signing message with path: {}", path);
        
        // In production, this would use Trezor's protocol
        let signature_data = format!("{}:{}", hex::encode(message), path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn get_public_key(&self, device_id: &str, path: &str) -> Result<Vec<u8>, HardwareWalletError> {
        // Simulate getting public key from Trezor
        println!("Trezor getting public key for path: {}", path);
        
        // In production, this would use Trezor's protocol
        let public_key = format!("trezor_public_key_{}", path);
        Ok(public_key.as_bytes().to_vec())
    }

    fn verify_pin(&self, device_id: &str, pin: &str) -> Result<bool, HardwareWalletError> {
        // Simulate PIN verification
        Ok(pin == "1234")
    }

    fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<(), HardwareWalletError> {
        // Simulate PIN change
        if old_pin == "1234" {
            println!("Trezor PIN changed from {} to {}", old_pin, new_pin);
            Ok(())
        } else {
            Err(HardwareWalletError::InvalidResponse("Invalid old PIN".to_string()))
        }
    }

    fn is_connected(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }
}

impl GenericHIDDriver {
    fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }
}

impl HardwareDriver for GenericHIDDriver {
    fn connect(&mut self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        // Simulate generic HID connection
        let device = HardwareDevice {
            device_id: device_id.to_string(),
            device_type: HardwareWalletType::GenericHID,
            name: "Generic HID Device".to_string(),
            firmware_version: "1.0.0".to_string(),
            connection_status: ConnectionStatus::Connected,
            connected_at: Some(Self::current_timestamp()),
            last_used: None,
            supported_features: vec![
                HardwareFeature::Ed25519Signing,
            ],
            derivation_paths: vec![
                "m/44'/1234'/0'/0/0".to_string(),
            ],
        };
        
        self.devices.insert(device_id.to_string(), device.clone());
        Ok(device)
    }

    fn disconnect(&mut self, device_id: &str) -> Result<(), HardwareWalletError> {
        self.devices.remove(device_id);
        Ok(())
    }

    fn get_device_info(&self, device_id: &str) -> Result<HardwareDevice, HardwareWalletError> {
        self.devices.get(device_id)
            .cloned()
            .ok_or_else(|| HardwareWalletError::DeviceNotFound(device_id.to_string()))
    }

    fn sign_transaction(&self, device_id: &str, transaction: &Transaction, path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate generic HID transaction signing
        println!("Generic HID signing transaction: {} with path: {}", transaction.hash, path);
        
        // In production, this would use HID protocol
        let signature_data = format!("{}:{}", transaction.hash, path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn sign_message(&self, device_id: &str, message: &[u8], path: &str) -> Result<Signature, HardwareWalletError> {
        // Simulate generic HID message signing
        println!("Generic HID signing message with path: {}", path);
        
        // In production, this would use HID protocol
        let signature_data = format!("{}:{}", hex::encode(message), path);
        let signature_bytes = signature_data.as_bytes();
        
        // Create a dummy signature
        let mut signature = [0u8; 64];
        signature[..signature_bytes.len().min(64)].copy_from_slice(&signature_bytes[..signature_bytes.len().min(64)]);
        
        Ok(Signature::from_bytes(SignatureKind::Ed25519, &signature).unwrap())
    }

    fn get_public_key(&self, device_id: &str, path: &str) -> Result<Vec<u8>, HardwareWalletError> {
        // Simulate getting public key from generic HID
        println!("Generic HID getting public key for path: {}", path);
        
        // In production, this would use HID protocol
        let public_key = format!("generic_public_key_{}", path);
        Ok(public_key.as_bytes().to_vec())
    }

    fn verify_pin(&self, device_id: &str, pin: &str) -> Result<bool, HardwareWalletError> {
        // Simulate PIN verification
        Ok(pin == "1234")
    }

    fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<(), HardwareWalletError> {
        // Simulate PIN change
        if old_pin == "1234" {
            println!("Generic HID PIN changed from {} to {}", old_pin, new_pin);
            Ok(())
        } else {
            Err(HardwareWalletError::InvalidResponse("Invalid old PIN".to_string()))
        }
    }

    fn is_connected(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }
}

// Helper trait for timestamp
trait Timestamp {
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Timestamp for LedgerDriver {}
impl Timestamp for TrezorDriver {}
impl Timestamp for GenericHIDDriver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Transaction;

    #[test]
    fn test_hardware_wallet_manager_creation() {
        let manager = HardwareWalletManager::new();
        assert_eq!(manager.config.max_retries, 3);
    }

    #[test]
    fn test_device_discovery() {
        let mut manager = HardwareWalletManager::new();
        let devices = manager.discover_devices();
        assert!(devices.is_ok());
    }

    #[test]
    fn test_ledger_connection() {
        let mut manager = HardwareWalletManager::new();
        let result = manager.connect_device("ledger_test", HardwareWalletType::LedgerNanoS);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_signing() {
        let mut manager = HardwareWalletManager::new();
        manager.connect_device("ledger_test", HardwareWalletType::LedgerNanoS).unwrap();
        
        let sender = Address::zero();
        let recipient = Address::zero();
        let amount = 1000;

        let mut transaction = Transaction {
            from: sender,
            to: recipient,
            amount,
            gas_limit: 21000,
            gas_price: 1,
            nonce: 0, // Would be fetched from network
            data: Vec::new(),
            signature: Signature::dummy(),
            hash: Hash::zero(), // Will be calculated
            fee: 0, // Will be calculated
            timestamp: HardwareWalletManager::current_timestamp(),
            tx_type: TransactionType::Transfer,
        };
        
        let result = manager.sign_transaction("ledger_test", &transaction, None);
        assert!(result.is_ok());
    }
} 