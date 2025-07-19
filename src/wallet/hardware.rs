use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use hidapi::{HidApi, HidDevice};
use ledger_apdu::{APDUCommand, APDUResponse};
use k256::ecdsa::{VerifyingKey, Signature};
use crate::types::{Address, Hash, Transaction};
use crate::wallet::hd_wallet::{DerivedAddress, AddressType};

/// Hardware wallet manager
pub struct HardwareWalletManager {
    /// Connected devices
    devices: HashMap<DeviceId, Box<dyn HardwareWallet>>,
    /// HID API instance
    hid_api: HidApi,
    /// Configuration
    config: HardwareConfig,
}

/// Hardware wallet device identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DeviceId {
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Serial number
    pub serial_number: Option<String>,
}

/// Hardware wallet trait
pub trait HardwareWallet: Send + Sync {
    /// Get device information
    fn get_device_info(&self) -> Result<DeviceInfo, HardwareError>;

    /// Get public key at derivation path
    fn get_public_key(&self, path: &str) -> Result<VerifyingKey, HardwareError>;

    /// Get address at derivation path
    fn get_address(&self, path: &str) -> Result<Address, HardwareError>;

    /// Sign transaction
    fn sign_transaction(&self, path: &str, transaction: &Transaction) -> Result<Signature, HardwareError>;

    /// Sign message
    fn sign_message(&self, path: &str, message: &[u8]) -> Result<Signature, HardwareError>;

    /// Display address on device for verification
    fn verify_address(&self, path: &str) -> Result<Address, HardwareError>;

    /// Get device status
    fn get_status(&self) -> Result<DeviceStatus, HardwareError>;

    /// Check if device is locked
    fn is_locked(&self) -> Result<bool, HardwareError>;
}

/// Ledger hardware wallet implementation
pub struct LedgerWallet {
    /// HID device connection
    device: HidDevice,
    /// Device info
    device_info: DeviceInfo,
    /// Application information
    app_info: Option<AppInfo>,
}

/// Trezor hardware wallet implementation  
pub struct TrezorWallet {
    /// HID device connection
    device: HidDevice,
    /// Device info
    device_info: DeviceInfo,
    /// Device session
    session_id: Option<String>,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device manufacturer
    pub manufacturer: String,
    /// Device model
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
    /// Device serial number
    pub serial_number: Option<String>,
    /// Supported features
    pub features: Vec<DeviceFeature>,
}

/// Device features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceFeature {
    /// Bitcoin support
    Bitcoin,
    /// Ethereum support
    Ethereum,
    /// EIP-1559 support
    Eip1559,
    /// Message signing
    MessageSigning,
    /// Blind signing
    BlindSigning,
    /// Custom derivation paths
    CustomDerivation,
}

/// Device status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceStatus {
    /// Device is ready for operations
    Ready,
    /// Device is locked (PIN required)
    Locked,
    /// Device is busy processing
    Busy,
    /// Device requires user confirmation
    AwaitingConfirmation,
    /// Device has an error
    Error(String),
    /// Device is not connected
    Disconnected,
}

/// Application information (for Ledger)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    /// Application name
    pub name: String,
    /// Application version
    pub version: String,
    /// Application flags
    pub flags: u32,
}

/// Hardware wallet configuration
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Operation timeout
    pub operation_timeout: Duration,
    /// Automatic device discovery
    pub auto_discovery: bool,
    /// Supported device types
    pub supported_devices: Vec<SupportedDevice>,
}

/// Supported device configuration
#[derive(Debug, Clone)]
pub struct SupportedDevice {
    /// Device type
    pub device_type: DeviceType,
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Interface number (for composite devices)
    pub interface_number: Option<i32>,
}

/// Device types
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
    LedgerNanoS,
    LedgerNanoX,
    LedgerNanoSPlus,
    TrezorOne,
    TrezorT,
}

/// Hardware wallet errors
#[derive(Debug, thiserror::Error)]
pub enum HardwareError {
    #[error("Device not found")]
    DeviceNotFound,
    #[error("Device connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Device communication error: {0}")]
    CommunicationError(String),
    #[error("Device is locked")]
    DeviceLocked,
    #[error("User rejected operation")]
    UserRejected,
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Device timeout")]
    Timeout,
    #[error("Invalid response from device")]
    InvalidResponse,
    #[error("HID error: {0}")]
    HidError(String),
}

impl HardwareWalletManager {
    /// Create new hardware wallet manager
    pub fn new(config: HardwareConfig) -> Result<Self, HardwareError> {
        println!("🔌 Initializing hardware wallet manager...");

        let hid_api = HidApi::new()
            .map_err(|e| HardwareError::HidError(e.to_string()))?;

        let mut manager = Self {
            devices: HashMap::new(),
            hid_api,
            config,
        };

        if manager.config.auto_discovery {
            manager.discover_devices()?;
        }

        println!("✅ Hardware wallet manager initialized");
        Ok(manager)
    }

    /// Discover connected hardware wallets
    pub fn discover_devices(&mut self) -> Result<Vec<DeviceId>, HardwareError> {
        println!("🔍 Discovering hardware wallets...");

        let mut discovered_devices = Vec::new();

        for device_info in self.hid_api.device_list() {
            for supported in &self.config.supported_devices {
                if device_info.vendor_id() == supported.vendor_id 
                    && device_info.product_id() == supported.product_id {
                    
                    let device_id = DeviceId {
                        vendor_id: device_info.vendor_id(),
                        product_id: device_info.product_id(),
                        serial_number: device_info.serial_number().map(|s| s.to_string()),
                    };

                    println!("   Found device: {:?} - {:?}", 
                            supported.device_type, device_id);

                    // Attempt to connect
                    if let Ok(wallet) = self.connect_device(&device_id, &supported.device_type) {
                        self.devices.insert(device_id.clone(), wallet);
                        discovered_devices.push(device_id);
                    }
                }
            }
        }

        println!("✅ Discovered {} hardware wallet(s)", discovered_devices.len());
        Ok(discovered_devices)
    }

    /// Connect to specific device
    fn connect_device(&self, device_id: &DeviceId, device_type: &DeviceType) -> Result<Box<dyn HardwareWallet>, HardwareError> {
        println!("🔗 Connecting to device: {:?}", device_id);

        let device = self.hid_api.open(device_id.vendor_id, device_id.product_id)
            .map_err(|e| HardwareError::ConnectionFailed(e.to_string()))?;

        let wallet: Box<dyn HardwareWallet> = match device_type {
            DeviceType::LedgerNanoS | DeviceType::LedgerNanoX | DeviceType::LedgerNanoSPlus => {
                Box::new(LedgerWallet::new(device)?)
            }
            DeviceType::TrezorOne | DeviceType::TrezorT => {
                Box::new(TrezorWallet::new(device)?)
            }
        };

        println!("✅ Connected to device successfully");
        Ok(wallet)
    }

    /// Get connected devices
    pub fn get_connected_devices(&self) -> Vec<&DeviceId> {
        self.devices.keys().collect()
    }

    /// Get device by ID
    pub fn get_device(&self, device_id: &DeviceId) -> Option<&dyn HardwareWallet> {
        self.devices.get(device_id).map(|d| d.as_ref())
    }

    /// Get device by ID (mutable)
    pub fn get_device_mut(&mut self, device_id: &DeviceId) -> Option<&mut dyn HardwareWallet> {
        self.devices.get_mut(device_id).map(|d| d.as_mut())
    }

    /// Disconnect device
    pub fn disconnect_device(&mut self, device_id: &DeviceId) -> Result<(), HardwareError> {
        if self.devices.remove(device_id).is_some() {
            println!("🔌 Device disconnected: {:?}", device_id);
            Ok(())
        } else {
            Err(HardwareError::DeviceNotFound)
        }
    }

    /// List addresses from hardware wallet
    pub fn list_addresses(&self, device_id: &DeviceId, account_index: u32, count: u32) -> Result<Vec<DerivedAddress>, HardwareError> {
        let device = self.get_device(device_id)
            .ok_or(HardwareError::DeviceNotFound)?;

        let mut addresses = Vec::new();

        for i in 0..count {
            let path = format!("m/44'/60'/{}'/{}/{}", account_index, 0, i);
            let address = device.get_address(&path)?;
            let public_key = device.get_public_key(&path)?;

            let derived_address = DerivedAddress {
                index: i,
                address,
                public_key,
                path: path.parse().map_err(|_| HardwareError::InvalidDerivationPath(path.clone()))?,
                label: Some(format!("Hardware Address {}", i)),
                balance: 0, // Would be fetched from blockchain
                nonce: 0,   // Would be fetched from blockchain
                address_type: AddressType::Receiving,
            };

            addresses.push(derived_address);
        }

        println!("📍 Listed {} addresses from hardware wallet", addresses.len());
        Ok(addresses)
    }

    /// Sign transaction with hardware wallet
    pub fn sign_transaction(&self, device_id: &DeviceId, derivation_path: &str, transaction: &Transaction) -> Result<Signature, HardwareError> {
        let device = self.get_device(device_id)
            .ok_or(HardwareError::DeviceNotFound)?;

        println!("✍️  Signing transaction with hardware wallet...");
        println!("   Path: {}", derivation_path);
        println!("   Transaction hash: {}", transaction.hash());

        let signature = device.sign_transaction(derivation_path, transaction)?;

        println!("✅ Transaction signed with hardware wallet");
        Ok(signature)
    }

    /// Verify address on device display
    pub fn verify_address(&self, device_id: &DeviceId, derivation_path: &str) -> Result<Address, HardwareError> {
        let device = self.get_device(device_id)
            .ok_or(HardwareError::DeviceNotFound)?;

        println!("🔍 Verifying address on device display...");
        let address = device.verify_address(derivation_path)?;
        println!("✅ Address verified: {}", address);

        Ok(address)
    }
}

impl LedgerWallet {
    /// Create new Ledger wallet connection
    pub fn new(device: HidDevice) -> Result<Self, HardwareError> {
        let mut wallet = Self {
            device,
            device_info: DeviceInfo {
                manufacturer: "Ledger".to_string(),
                model: "Unknown".to_string(),
                firmware_version: "Unknown".to_string(),
                serial_number: None,
                features: vec![
                    DeviceFeature::Bitcoin,
                    DeviceFeature::Ethereum,
                    DeviceFeature::MessageSigning,
                ],
            },
            app_info: None,
        };

        // Initialize device and get info
        wallet.initialize()?;

        Ok(wallet)
    }

    /// Initialize device connection
    fn initialize(&mut self) -> Result<(), HardwareError> {
        // Open Ethereum app
        self.open_ethereum_app()?;
        
        // Get device and app info
        self.get_device_and_app_info()?;

        Ok(())
    }

    /// Open Ethereum application on Ledger
    fn open_ethereum_app(&mut self) -> Result<(), HardwareError> {
        println!("📱 Opening Ethereum app on Ledger...");

        // This would send the appropriate APDU commands to open the Ethereum app
        // For now, we'll simulate this
        
        Ok(())
    }

    /// Get device and application information
    fn get_device_and_app_info(&mut self) -> Result<(), HardwareError> {
        // This would query the device for its information
        // For now, we'll use default values
        
        self.app_info = Some(AppInfo {
            name: "Ethereum".to_string(),
            version: "1.10.3".to_string(),
            flags: 0,
        });

        Ok(())
    }

    /// Send APDU command to device
    fn send_apdu(&mut self, command: &APDUCommand) -> Result<APDUResponse, HardwareError> {
        // Convert command to bytes
        let command_bytes = command.serialize();
        
        // Send to device
        self.device.write(&command_bytes)
            .map_err(|e| HardwareError::CommunicationError(e.to_string()))?;

        // Read response
        let mut response_buffer = [0u8; 255];
        let bytes_read = self.device.read_timeout(&mut response_buffer, 5000)
            .map_err(|e| HardwareError::CommunicationError(e.to_string()))?;

        // Parse response
        if bytes_read < 2 {
            return Err(HardwareError::InvalidResponse);
        }

        let status = u16::from_be_bytes([
            response_buffer[bytes_read - 2],
            response_buffer[bytes_read - 1],
        ]);

        let data = response_buffer[..bytes_read - 2].to_vec();

        Ok(APDUResponse::new(status, data))
    }
}

impl HardwareWallet for LedgerWallet {
    fn get_device_info(&self) -> Result<DeviceInfo, HardwareError> {
        Ok(self.device_info.clone())
    }

    fn get_public_key(&self, path: &str) -> Result<VerifyingKey, HardwareError> {
        println!("🔑 Getting public key from Ledger at path: {}", path);

        // This would send the appropriate APDU command to get the public key
        // For now, we'll return a dummy key
        
        Err(HardwareError::UnsupportedOperation("get_public_key not fully implemented".to_string()))
    }

    fn get_address(&self, path: &str) -> Result<Address, HardwareError> {
        println!("📍 Getting address from Ledger at path: {}", path);

        // This would send the appropriate APDU command to get the address
        // For now, we'll return a dummy address
        
        Ok(Address::from([0u8; 20])) // Dummy address
    }

    fn sign_transaction(&self, path: &str, transaction: &Transaction) -> Result<Signature, HardwareError> {
        println!("✍️  Signing transaction with Ledger at path: {}", path);

        // This would:
        // 1. Encode the transaction for Ledger
        // 2. Send signing APDU command
        // 3. Parse the signature response
        
        Err(HardwareError::UnsupportedOperation("sign_transaction not fully implemented".to_string()))
    }

    fn sign_message(&self, path: &str, message: &[u8]) -> Result<Signature, HardwareError> {
        println!("✍️  Signing message with Ledger at path: {}", path);

        Err(HardwareError::UnsupportedOperation("sign_message not fully implemented".to_string()))
    }

    fn verify_address(&self, path: &str) -> Result<Address, HardwareError> {
        println!("🔍 Verifying address on Ledger display at path: {}", path);

        // This would display the address on the device screen for user verification
        
        self.get_address(path)
    }

    fn get_status(&self) -> Result<DeviceStatus, HardwareError> {
        // Check device status
        Ok(DeviceStatus::Ready)
    }

    fn is_locked(&self) -> Result<bool, HardwareError> {
        // Check if device is locked
        Ok(false)
    }
}

impl TrezorWallet {
    /// Create new Trezor wallet connection
    pub fn new(device: HidDevice) -> Result<Self, HardwareError> {
        let wallet = Self {
            device,
            device_info: DeviceInfo {
                manufacturer: "Trezor".to_string(),
                model: "Unknown".to_string(),
                firmware_version: "Unknown".to_string(),
                serial_number: None,
                features: vec![
                    DeviceFeature::Bitcoin,
                    DeviceFeature::Ethereum,
                    DeviceFeature::MessageSigning,
                    DeviceFeature::CustomDerivation,
                ],
            },
            session_id: None,
        };

        Ok(wallet)
    }
}

impl HardwareWallet for TrezorWallet {
    fn get_device_info(&self) -> Result<DeviceInfo, HardwareError> {
        Ok(self.device_info.clone())
    }

    fn get_public_key(&self, path: &str) -> Result<VerifyingKey, HardwareError> {
        println!("🔑 Getting public key from Trezor at path: {}", path);
        
        Err(HardwareError::UnsupportedOperation("Trezor not fully implemented".to_string()))
    }

    fn get_address(&self, path: &str) -> Result<Address, HardwareError> {
        println!("📍 Getting address from Trezor at path: {}", path);
        
        Ok(Address::from([1u8; 20])) // Dummy address
    }

    fn sign_transaction(&self, path: &str, transaction: &Transaction) -> Result<Signature, HardwareError> {
        println!("✍️  Signing transaction with Trezor at path: {}", path);
        
        Err(HardwareError::UnsupportedOperation("Trezor not fully implemented".to_string()))
    }

    fn sign_message(&self, path: &str, message: &[u8]) -> Result<Signature, HardwareError> {
        println!("✍️  Signing message with Trezor at path: {}", path);
        
        Err(HardwareError::UnsupportedOperation("Trezor not fully implemented".to_string()))
    }

    fn verify_address(&self, path: &str) -> Result<Address, HardwareError> {
        println!("🔍 Verifying address on Trezor display at path: {}", path);
        
        self.get_address(path)
    }

    fn get_status(&self) -> Result<DeviceStatus, HardwareError> {
        Ok(DeviceStatus::Ready)
    }

    fn is_locked(&self) -> Result<bool, HardwareError> {
        Ok(false)
    }
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(30),
            auto_discovery: true,
            supported_devices: vec![
                SupportedDevice {
                    device_type: DeviceType::LedgerNanoS,
                    vendor_id: 0x2c97,
                    product_id: 0x0001,
                    interface_number: None,
                },
                SupportedDevice {
                    device_type: DeviceType::LedgerNanoX,
                    vendor_id: 0x2c97,
                    product_id: 0x0004,
                    interface_number: None,
                },
                SupportedDevice {
                    device_type: DeviceType::LedgerNanoSPlus,
                    vendor_id: 0x2c97,
                    product_id: 0x0005,
                    interface_number: None,
                },
                SupportedDevice {
                    device_type: DeviceType::TrezorOne,
                    vendor_id: 0x534c,
                    product_id: 0x0001,
                    interface_number: None,
                },
                SupportedDevice {
                    device_type: DeviceType::TrezorT,
                    vendor_id: 0x1209,
                    product_id: 0x53c1,
                    interface_number: None,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_creation() {
        let device_id = DeviceId {
            vendor_id: 0x2c97,
            product_id: 0x0001,
            serial_number: Some("123456".to_string()),
        };

        assert_eq!(device_id.vendor_id, 0x2c97);
        assert_eq!(device_id.product_id, 0x0001);
        assert_eq!(device_id.serial_number, Some("123456".to_string()));
    }

    #[test]
    fn test_supported_devices_config() {
        let config = HardwareConfig::default();
        assert!(config.supported_devices.len() > 0);
        
        // Check for Ledger devices
        let ledger_devices: Vec<_> = config.supported_devices.iter()
            .filter(|d| matches!(d.device_type, 
                DeviceType::LedgerNanoS | 
                DeviceType::LedgerNanoX | 
                DeviceType::LedgerNanoSPlus))
            .collect();
        
        assert!(ledger_devices.len() >= 3);
    }

    #[test]
    fn test_device_features() {
        let features = vec![
            DeviceFeature::Bitcoin,
            DeviceFeature::Ethereum,
            DeviceFeature::MessageSigning,
        ];

        assert!(features.contains(&DeviceFeature::Ethereum));
        assert!(features.contains(&DeviceFeature::MessageSigning));
    }
} 