use alloy::{
    hex,
    primitives::{Address, FixedBytes, U256},
};
use clap::Parser;
use smart_account_oracle::{
    calculate_create2_address, calculate_salt_from_initializer, parse_hex_bytes, parse_u256,
};

#[derive(Parser)]
#[command(name = "safe-oracle")]
#[command(about = "Calculate CREATE2 address from factory address, salt, and init code hash")]
struct Args {
    /// Factory contract address (20 bytes hex, with or without 0x prefix)
    #[arg(long, default_value = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67")]
    factory: String,

    /// Salt value (32 bytes hex, with or without 0x prefix). If not provided, will be calculated from saltNonce and initializer
    #[arg(long)]
    salt: Option<String>,

    /// Salt nonce value (32 bytes hex, used to calculate salt combined with the initializer)
    #[arg(long, value_parser = parse_u256)]
    salt_nonce: Option<U256>,

    /// Initializer data (hex string of the initializer code)
    #[arg(long)]
    initializer: Option<String>,

    /// Init code hash (32 bytes hex, with or without 0x prefix)
    #[arg(
        long,
        default_value = "0x76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb"
    )]
    init_code_hash: String,
}

fn main() {
    let args = Args::parse();

    // Parse factory address
    let factory_address = args.factory.parse::<Address>().unwrap_or_else(|e| {
        eprintln!("Error parsing factory address: {}", e);
        std::process::exit(1);
    });

    // Parse or calculate salt
    let salt = match args.salt.as_ref() {
        Some(salt_str) => {
            // Salt provided directly
            let salt_bytes = parse_hex_bytes(salt_str, 32).unwrap_or_else(|e| {
                eprintln!("Error parsing salt: {}", e);
                std::process::exit(1);
            });
            FixedBytes::<32>::from_slice(&salt_bytes)
        }
        None => {
            // Calculate salt from initializer and salt_nonce
            match (args.initializer.as_ref(), args.salt_nonce) {
                (Some(initializer), Some(salt_nonce)) => {
                    calculate_salt_from_initializer(initializer, salt_nonce)
                }
                _ => {
                    eprintln!(
                        "Error: Either provide --salt directly, or provide both --initializer and --salt-nonce"
                    );
                    std::process::exit(1);
                }
            }
        }
    };

    // Parse init code hash (32 bytes)
    let init_code_hash_bytes = parse_hex_bytes(&args.init_code_hash, 32).unwrap_or_else(|e| {
        eprintln!("Error parsing init code hash: {}", e);
        std::process::exit(1);
    });
    let init_code_hash = FixedBytes::<32>::from_slice(&init_code_hash_bytes);

    // Calculate CREATE2 address
    let create2_address = calculate_create2_address(factory_address, salt, init_code_hash);

    // Display results
    println!("CREATE2 Address Calculation");
    println!("==========================");
    println!("Factory Address: {}", factory_address);
    println!("Salt: 0x{}", hex::encode(salt.as_slice()));
    if let (Some(initializer), Some(salt_nonce)) = (args.initializer.as_ref(), args.salt_nonce) {
        println!("  (Calculated from initializer and salt nonce)");
        println!("  Initializer: {}", initializer);
        println!("  Salt Nonce: {:#x}", salt_nonce);
    }
    println!(
        "Init Code Hash: 0x{}",
        hex::encode(init_code_hash.as_slice())
    );
    println!("CREATE2 Address: {}", create2_address);
}
