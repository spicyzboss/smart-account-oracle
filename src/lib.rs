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

/// Fast count of leading zeros working directly with address bytes
pub fn count_leading_zeros_fast(address: &Address) -> u8 {
    let bytes = address.as_slice();
    let mut count = 0u8;
    
    for &byte in bytes {
        if byte == 0 {
            count += 2; // Each zero byte = 2 hex zeros
        } else if byte < 0x10 {
            count += 1; // High nibble is zero
            break;
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

/// Fast pattern matching working directly with address bytes
pub fn matches_pattern_fast(
    address: &Address,
    pattern_bytes: &[u8],
    mode: &MatchMode,
    case_sensitive: bool,
) -> bool {
    let addr_bytes = address.as_slice();
    
    match mode {
        MatchMode::LeadingZeros => false, // Handle separately
        MatchMode::StartsWith => {
            if case_sensitive {
                starts_with_bytes(addr_bytes, pattern_bytes)
            } else {
                starts_with_bytes_case_insensitive(addr_bytes, pattern_bytes)
            }
        }
        MatchMode::EndsWith => {
            if case_sensitive {
                ends_with_bytes(addr_bytes, pattern_bytes)
            } else {
                ends_with_bytes_case_insensitive(addr_bytes, pattern_bytes)
            }
        }
        MatchMode::Contains => {
            if case_sensitive {
                contains_bytes(addr_bytes, pattern_bytes)
            } else {
                contains_bytes_case_insensitive(addr_bytes, pattern_bytes)
            }
        }
    }
}

fn starts_with_bytes(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    for (i, &pattern_byte) in pattern.iter().enumerate() {
        let addr_idx = i / 2;
        let addr_byte = addr[addr_idx];
        let addr_nibble = if i % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
        
        if pattern_byte != addr_nibble {
            return false;
        }
    }
    true
}

fn starts_with_bytes_case_insensitive(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    for (i, &pattern_byte) in pattern.iter().enumerate() {
        let addr_idx = i / 2;
        let addr_byte = addr[addr_idx];
        let addr_nibble = if i % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
        
        // Convert both to lowercase for comparison
        let pattern_lower = if pattern_byte >= 10 { pattern_byte - 10 + b'a' } else { pattern_byte + b'0' };
        let addr_lower = if addr_nibble >= 10 { addr_nibble - 10 + b'a' } else { addr_nibble + b'0' };
        
        if pattern_lower != addr_lower {
            return false;
        }
    }
    true
}

fn ends_with_bytes(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    let start_pos = addr.len() * 2 - pattern.len();
    for (i, &pattern_byte) in pattern.iter().enumerate() {
        let pos = start_pos + i;
        let addr_idx = pos / 2;
        let addr_byte = addr[addr_idx];
        let addr_nibble = if pos % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
        
        if pattern_byte != addr_nibble {
            return false;
        }
    }
    true
}

fn ends_with_bytes_case_insensitive(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    let start_pos = addr.len() * 2 - pattern.len();
    for (i, &pattern_byte) in pattern.iter().enumerate() {
        let pos = start_pos + i;
        let addr_idx = pos / 2;
        let addr_byte = addr[addr_idx];
        let addr_nibble = if pos % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
        
        let pattern_lower = if pattern_byte >= 10 { pattern_byte - 10 + b'a' } else { pattern_byte + b'0' };
        let addr_lower = if addr_nibble >= 10 { addr_nibble - 10 + b'a' } else { addr_nibble + b'0' };
        
        if pattern_lower != addr_lower {
            return false;
        }
    }
    true
}

fn contains_bytes(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    for start in 0..=(addr.len() * 2 - pattern.len()) {
        let mut matches = true;
        for (i, &pattern_byte) in pattern.iter().enumerate() {
            let pos = start + i;
            let addr_idx = pos / 2;
            let addr_byte = addr[addr_idx];
            let addr_nibble = if pos % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
            
            if pattern_byte != addr_nibble {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

fn contains_bytes_case_insensitive(addr: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > addr.len() * 2 {
        return false;
    }
    
    for start in 0..=(addr.len() * 2 - pattern.len()) {
        let mut matches = true;
        for (i, &pattern_byte) in pattern.iter().enumerate() {
            let pos = start + i;
            let addr_idx = pos / 2;
            let addr_byte = addr[addr_idx];
            let addr_nibble = if pos % 2 == 0 { addr_byte >> 4 } else { addr_byte & 0x0f };
            
            let pattern_lower = if pattern_byte >= 10 { pattern_byte - 10 + b'a' } else { pattern_byte + b'0' };
            let addr_lower = if addr_nibble >= 10 { addr_nibble - 10 + b'a' } else { addr_nibble + b'0' };
            
            if pattern_lower != addr_lower {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

/// Validate a hex pattern for address matching
pub fn validate_hex_pattern(pattern: &str) -> Result<(), String> {
    let pattern_clean = pattern.to_lowercase();
    if !pattern_clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Pattern must contain only hexadecimal characters (0-9, a-f)".to_string());
    }
    Ok(())
}

/// Convert hex pattern string to byte nibbles for fast matching
pub fn parse_pattern_to_nibbles(pattern: &str) -> Result<Vec<u8>, String> {
    let pattern_clean = pattern.to_lowercase();
    if !pattern_clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Pattern must contain only hexadecimal characters (0-9, a-f)".to_string());
    }
    
    let mut nibbles = Vec::with_capacity(pattern_clean.len());
    for ch in pattern_clean.chars() {
        let nibble = match ch {
            '0'..='9' => ch as u8 - b'0',
            'a'..='f' => ch as u8 - b'a' + 10,
            _ => return Err("Invalid hex character".to_string()),
        };
        nibbles.push(nibble);
    }
    Ok(nibbles)
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

/// Optimized CREATE2 address calculation that reuses buffer
pub fn calculate_create2_address_fast(
    factory_address: Address,
    salt: FixedBytes<32>,
    init_code_hash: FixedBytes<32>,
    buffer: &mut [u8; 85], // Pre-allocated buffer
) -> Address {
    // Prepare the data for hashing: 0xff + factory_address + salt + init_code_hash
    buffer[0] = 0xff;
    buffer[1..21].copy_from_slice(factory_address.as_slice());
    buffer[21..53].copy_from_slice(salt.as_slice());
    buffer[53..85].copy_from_slice(init_code_hash.as_slice());

    // Hash the data and take the last 20 bytes as the address
    let hash = keccak256(buffer);
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

/// Fast salt calculation using pre-computed initializer hash
pub fn calculate_salt_from_initializer_hash_fast(
    initializer_hash: FixedBytes<32>,
    salt_nonce: U256,
) -> FixedBytes<32> {
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

/// Pre-compute initializer hash for performance
pub fn precompute_initializer_hash(initializer: &str) -> Result<FixedBytes<32>, String> {
    let initializer_bytes = parse_hex_string(initializer)?;
    Ok(keccak256(&initializer_bytes))
}

/// Optimized vanity address generation that minimizes allocations
pub fn generate_vanity_address_fast(
    factory_address: Address,
    init_code_hash: FixedBytes<32>,
    initializer_hash: FixedBytes<32>, // Pre-computed
    salt_nonce: U256,
    buffer: &mut [u8; 85], // Reused buffer
) -> (Address, FixedBytes<32>) {
    let salt = calculate_salt_from_initializer_hash_fast(initializer_hash, salt_nonce);
    let address = calculate_create2_address_fast(factory_address, salt, init_code_hash, buffer);
    (address, salt)
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
