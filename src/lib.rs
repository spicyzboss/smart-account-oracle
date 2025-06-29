use alloy::{
    hex,
    primitives::{Address, FixedBytes, U256, keccak256},
    sol_types::SolValue,
};
use std::fmt;

/// Matching mode for vanity address generation
#[derive(Clone, Debug)]
pub enum MatchMode {
    StartsWith,
    EndsWith,
    Contains,
    LeadingZeros,
}

impl fmt::Display for MatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchMode::StartsWith => write!(f, "starts with"),
            MatchMode::EndsWith => write!(f, "ends with"),
            MatchMode::Contains => write!(f, "contains"),
            MatchMode::LeadingZeros => write!(f, "leading zeros"),
        }
    }
}

/// Result of a vanity address search
#[derive(Debug, Clone)]
pub struct VanityResult {
    pub singleton: Option<Address>,
    pub initializer: String,
    pub address: Address,
    pub salt_nonce: U256,
    pub attempts: u64,
    pub leading_zeros: u8,
}

impl VanityResult {
    pub fn new(
        singleton: Option<Address>,
        initializer: String,
        address: Address,
        salt_nonce: U256,
        attempts: u64,
    ) -> Self {
        let leading_zeros = count_leading_zeros(&address);
        Self {
            singleton,
            initializer,
            address,
            salt_nonce,
            attempts,
            leading_zeros,
        }
    }
}

/// Count leading zeros in an address
pub fn count_leading_zeros(address: &Address) -> u8 {
    let address_str = format!("{:?}", address);
    let address_clean = &address_str[2..]; // Remove "0x" prefix

    let mut count = 0u8;
    for ch in address_clean.chars() {
        if ch == '0' {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Check if an address matches a pattern based on the mode
pub fn matches_pattern(
    address: &Address,
    pattern: &str,
    mode: &MatchMode,
    case_sensitive: bool,
) -> bool {
    match mode {
        MatchMode::LeadingZeros => false, // Handle separately in caller
        _ => {
            let address_str = format!("{:?}", address);
            let address_clean = &address_str[2..]; // Remove "0x" prefix

            let (addr, pat) = if case_sensitive {
                (address_clean.to_string(), pattern.to_string())
            } else {
                (address_clean.to_lowercase(), pattern.to_lowercase())
            };

            match mode {
                MatchMode::StartsWith => addr.starts_with(&pat),
                MatchMode::EndsWith => addr.ends_with(&pat),
                MatchMode::Contains => addr.contains(&pat),
                MatchMode::LeadingZeros => unreachable!(),
            }
        }
    }
}

/// Validate a hex pattern for address matching
pub fn validate_hex_pattern(pattern: &str) -> Result<(), String> {
    let pattern_clean = pattern.to_lowercase();
    if !pattern_clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Pattern must contain only hexadecimal characters (0-9, a-f)".to_string());
    }
    Ok(())
}

/// Generate a random vanity address using CREATE2
pub fn generate_vanity_address(
    factory_address: Address,
    init_code_hash: FixedBytes<32>,
    initializer: &str,
    salt_nonce: U256,
) -> (Address, FixedBytes<32>) {
    let salt = calculate_salt_from_initializer(initializer, salt_nonce);
    let address = calculate_create2_address(factory_address, salt, init_code_hash);
    (address, salt)
}

/// Format attempts with thousands separators
pub fn format_attempts(attempts: u64) -> String {
    let mut result = String::new();
    let attempts_str = attempts.to_string();
    let chars: Vec<char> = attempts_str.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }

    result
}

/// Format rate with appropriate units
pub fn format_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 {
        format!("{:.1}M", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1}K", rate / 1_000.0)
    } else {
        format!("{:.0}", rate)
    }
}

/// Parse a U256 from a string (supports decimal, 0x hex, and plain hex)
pub fn parse_u256(s: &str) -> Result<U256, String> {
    if s.starts_with("0x") {
        U256::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex U256: {}", e))
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 10 {
        // Assume hex if it's all hex digits and longer than a typical decimal
        U256::from_str_radix(s, 16).map_err(|e| format!("Invalid hex U256: {}", e))
    } else {
        s.parse::<U256>()
            .map_err(|e| format!("Invalid decimal U256: {}", e))
    }
}

/// Calculate CREATE2 address from factory address, salt, and init code hash
/// Formula: address = keccak256(0xff ++ factory_address ++ salt ++ init_code_hash)[12:]
pub fn calculate_create2_address(
    factory_address: Address,
    salt: FixedBytes<32>,
    init_code_hash: FixedBytes<32>,
) -> Address {
    // Prepare the data for hashing: 0xff + factory_address + salt + init_code_hash
    let mut data = Vec::with_capacity(1 + 20 + 32 + 32); // 85 bytes total

    // Add 0xff prefix
    data.push(0xff);

    // Add factory address (20 bytes)
    data.extend_from_slice(factory_address.as_slice());

    // Add salt (32 bytes)
    data.extend_from_slice(salt.as_slice());

    // Add init code hash (32 bytes)
    data.extend_from_slice(init_code_hash.as_slice());

    // Hash the data and take the last 20 bytes as the address
    let hash = keccak256(&data);
    Address::from_slice(&hash[12..])
}

/// Calculate salt from initializer and salt nonce using the formula:
/// keccak256(abi.encodePacked(keccak256(initializer), saltNonce))
pub fn calculate_salt_from_initializer(initializer: &str, salt_nonce: U256) -> FixedBytes<32> {
    // Parse initializer hex string
    let initializer_bytes = parse_hex_string(initializer).unwrap_or_else(|e| {
        eprintln!("Error parsing initializer: {}", e);
        std::process::exit(1);
    });

    // Hash the initializer
    let initializer_hash = keccak256(&initializer_bytes);

    // Convert salt_nonce to big-endian bytes (32 bytes for U256)
    let salt_nonce_bytes = salt_nonce.to_be_bytes::<32>();

    // Concatenate: initializer_hash (32 bytes) + salt_nonce_bytes (32 bytes)
    let packed_data = [initializer_hash.to_vec(), salt_nonce_bytes.to_vec()].abi_encode_packed();

    // Hash the packed data
    keccak256(&packed_data)
}

/// Helper function to parse hex string (with or without 0x prefix) of any length
pub fn parse_hex_string(hex_str: &str) -> Result<Vec<u8>, String> {
    let cleaned = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        hex_str
    };

    hex::decode(cleaned).map_err(|e| format!("Invalid hex string: {}", e))
}

/// Helper function to parse hex string (with or without 0x prefix)
pub fn parse_hex_bytes(hex_str: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let cleaned = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        hex_str
    };

    let bytes = hex::decode(cleaned).map_err(|e| format!("Invalid hex string: {}", e))?;

    if bytes.len() != expected_len {
        return Err(format!(
            "Expected {} bytes, got {}",
            expected_len,
            bytes.len()
        ));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_create2_address() {
        let factory_address = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
            .parse::<Address>()
            .unwrap();
        let init_code_hash = "0x76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb"
            .parse::<FixedBytes<32>>()
            .unwrap();
        let salt = "0x1d4547d3c1251a046e09cd24aea24778f388e6cb3a17ca75c6ebb91676992373"
            .parse::<FixedBytes<32>>()
            .unwrap();

        let create2_address = calculate_create2_address(factory_address, salt, init_code_hash);
        assert_eq!(
            create2_address,
            "0x82d647b02d4704cb2aa5e12624ba3681a846ab36"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_calculate_create2_address_with_salt_nonce() {
        let factory_address = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
            .parse::<Address>()
            .unwrap();
        let salt_nonce = U256::from(0);
        let initializer = "0xb63e800d00000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000bd89a1ce4dde368ffab0ec35506eece0b1ffdc540000000000000000000000000000000000000000000000000000000000000180000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec99000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005afe7a11e7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000077779215df514504a44ad75184d946f1c20c7777000000000000000000000000000016de322633fac520f42e28d1dc5a85d6000000000000000000000000000077777b0283cb1c76d0f7707b5701c98e42c777770000000000000000000000000000000000000000000000000000000000000024fe51f64300000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c76200000000000000000000000000000000000000000000000000000000";
        let init_code_hash = "0x76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb"
            .parse::<FixedBytes<32>>()
            .unwrap();

        let salt = calculate_salt_from_initializer(initializer, salt_nonce);
        assert_eq!(
            salt,
            "0x1d4547d3c1251a046e09cd24aea24778f388e6cb3a17ca75c6ebb91676992373"
                .parse::<FixedBytes<32>>()
                .unwrap()
        );

        let create2_address = calculate_create2_address(factory_address, salt, init_code_hash);
        assert_eq!(
            create2_address,
            "0x82d647b02d4704cb2aa5e12624ba3681a846ab36"
                .parse::<Address>()
                .unwrap()
        );
    }
}
