use alloy::{
    hex,
    primitives::{Address, FixedBytes, U256, keccak256},
    sol_types::SolValue,
};

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