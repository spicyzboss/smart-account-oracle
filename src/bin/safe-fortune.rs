use alloy::primitives::{Address, FixedBytes, U256};
use clap::{Parser, ValueEnum};
use crossbeam::channel::{Receiver, Sender, unbounded};
use rand::Rng;
use smart_account_oracle::{
    MatchMode, VanityResult, count_leading_zeros, format_attempts, format_rate,
    generate_vanity_address, matches_pattern, parse_hex_string, validate_hex_pattern,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "safe-fortune")]
#[command(about = "Generate vanity addresses using CREATE2 with customizable patterns")]
struct Cli {
    /// Factory address for CREATE2 deployment
    #[arg(
        long,
        value_name = "ADDRESS",
        default_value = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
    )]
    factory: String,

    /// Singleton address for CREATE2 deployment (experimental)
    #[arg(
        long,
        value_name = "ADDRESS",
        default_value = "0x41675C099F32341bf84BFc5382aF534df5C7461a"
    )]
    singleton: Option<String>,

    /// Init code hash for CREATE2 calculation
    #[arg(
        long,
        value_name = "HASH",
        default_value = "0x76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb"
    )]
    init_code_hash: String,

    /// Initializer data (hex string)
    #[arg(long, value_name = "HEX")]
    initializer: String,

    /// Pattern to match in the address (not required for leading-zeros mode)
    #[arg(long, value_name = "PATTERN")]
    pattern: Option<String>,

    /// Pattern matching mode
    #[arg(long, value_enum, default_value = "starts-with")]
    mode: CliMatchMode,

    /// Number of worker threads (0 = auto-detect CPU cores)
    #[arg(long, default_value = "0")]
    jobs: usize,

    /// Case sensitive matching
    #[arg(long)]
    case_sensitive: bool,

    /// Maximum attempts before giving up (0 = unlimited)
    #[arg(long, default_value = "0")]
    max_attempts: u64,
}

#[derive(Clone, ValueEnum)]
enum CliMatchMode {
    #[value(name = "starts-with")]
    StartsWith,
    #[value(name = "ends-with")]
    EndsWith,
    #[value(name = "contains")]
    Contains,
    #[value(name = "leading-zeros")]
    LeadingZeros,
}

impl From<CliMatchMode> for MatchMode {
    fn from(cli_mode: CliMatchMode) -> Self {
        match cli_mode {
            CliMatchMode::StartsWith => MatchMode::StartsWith,
            CliMatchMode::EndsWith => MatchMode::EndsWith,
            CliMatchMode::Contains => MatchMode::Contains,
            CliMatchMode::LeadingZeros => MatchMode::LeadingZeros,
        }
    }
}

fn worker(
    factory_address: Address,
    init_code_hash: FixedBytes<32>,
    initializer: String,
    pattern: Option<String>,
    mode: MatchMode,
    case_sensitive: bool,
    sender: Sender<VanityResult>,
    stop_flag: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    singleton: Option<Address>,
    max_leading_zeros: Arc<AtomicU8>,
    starting_salt_nonce: U256,
) {
    let mut salt_nonce = starting_salt_nonce;
    let mut attempts = 0u64;

    while !stop_flag.load(Ordering::Relaxed) {
        attempts += 1;
        counter.fetch_add(1, Ordering::Relaxed);

        // Generate address with current salt nonce
        let (address, _salt) =
            generate_vanity_address(factory_address, init_code_hash, &initializer, salt_nonce);

        let should_report = match mode {
            MatchMode::LeadingZeros => {
                let leading_zeros = count_leading_zeros(&address);
                let current_max = max_leading_zeros.load(Ordering::Relaxed);

                if leading_zeros > current_max {
                    max_leading_zeros
                        .compare_exchange_weak(
                            current_max,
                            leading_zeros,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                } else {
                    false
                }
            }
            _ => {
                if let Some(ref pattern) = pattern {
                    matches_pattern(&address, pattern, &mode, case_sensitive)
                } else {
                    false
                }
            }
        };

        if should_report {
            let result = VanityResult::new(
                singleton,
                initializer.clone(),
                address,
                salt_nonce,
                attempts,
            );

            if sender.send(result).is_err() {
                break; // Main thread disconnected
            }

            if !matches!(mode, MatchMode::LeadingZeros) {
                break; // Found a match, stop this worker (except for leading zeros mode)
            }
        }

        // Increment salt nonce for next iteration
        salt_nonce = salt_nonce.wrapping_add(U256::from(1));
    }
}

fn print_progress(
    counter: Arc<AtomicU64>,
    start_time: Instant,
    max_leading_zeros: Arc<AtomicU8>,
    mode: MatchMode,
) {
    use std::io::{self, Write};
    let mut last_count = 0u64;

    loop {
        let current_count = counter.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64();
        let avg_rate = if elapsed > 0.0 { current_count as f64 / elapsed } else { 0.0 };
        let current_rate = (current_count - last_count) as f64;

        if current_count > 0 {
            match mode {
                MatchMode::LeadingZeros => {
                    let current_max = max_leading_zeros.load(Ordering::Relaxed);
                    print!(
                        "\r⚡ Attempts: {} | Rate: {}/s (avg: {}/s) | Max Leading Zeros: {} | Elapsed: {:.0}s",
                        format_attempts(current_count),
                        format_rate(current_rate),
                        format_rate(avg_rate),
                        current_max,
                        elapsed
                    );
                }
                _ => {
                    print!(
                        "\r⚡ Attempts: {} | Rate: {}/s (avg: {}/s) | Elapsed: {:.0}s",
                        format_attempts(current_count),
                        format_rate(current_rate),
                        format_rate(avg_rate),
                        elapsed
                    );
                }
            }
            io::stdout().flush().unwrap();
        }

        last_count = current_count;
        
        // Update every second
        thread::sleep(Duration::from_secs(1));
    }
}

fn print_result_summary(result: &VanityResult, total_attempts: u64, elapsed: Duration) {
    let mut output = String::from("\n===========================================================\n");

    output.push_str(&format!("Address:         {:#x}\n", result.address));
    if let Some(singleton) = result.singleton {
        output.push_str(&format!("Singleton:       {:#x}\n", singleton));
    }
    output.push_str(&format!("Initializer:     {}\n", result.initializer));
    output.push_str(&format!("Salt Nonce:      {:#x} ({})\n", result.salt_nonce, result.salt_nonce));
    output.push_str("-----------------------------------------------------------\n");
    output.push_str(&format!("Leading Zeros:   {}\n", result.leading_zeros));
    output.push_str(&format!("Worker Attempts: {}\n", format_attempts(result.attempts)));
    output.push_str(&format!("Total Attempts:  {}\n", format_attempts(total_attempts)));
    output.push_str(&format!("Time Elapsed:    {:.0}s\n", elapsed.as_secs_f64()));
    output.push_str(&format!("Average Rate:    {}/sec\n", format_rate(total_attempts as f64 / elapsed.as_secs_f64())));
    output.push_str("===========================================================\n");
    
    print!("{}", output);
}

fn validate_inputs(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Validate factory address
    cli.factory
        .parse::<Address>()
        .map_err(|e| format!("Invalid factory address: {}", e))?;

    // Validate init code hash
    cli.init_code_hash
        .parse::<FixedBytes<32>>()
        .map_err(|e| format!("Invalid init code hash: {}", e))?;

    // Validate initializer hex string
    parse_hex_string(&cli.initializer).map_err(|e| format!("Invalid initializer hex: {}", e))?;

    // Validate pattern (not required for leading-zeros mode)
    let mode: MatchMode = cli.mode.clone().into();
    if !matches!(mode, MatchMode::LeadingZeros) {
        if cli.pattern.is_none() || cli.pattern.as_ref().unwrap().is_empty() {
            return Err("Pattern is required for non-leading-zeros modes".into());
        }

        if let Some(ref pattern) = cli.pattern {
            validate_hex_pattern(pattern).map_err(|e| format!("Invalid pattern: {}", e))?;
        }
    }

    Ok(())
}

fn print_configuration(cli: &Cli, factory_address: Address, init_code_hash: FixedBytes<32>) {
    let mode: MatchMode = cli.mode.clone().into();

    println!("============================");
    println!("Factory Address: {}", factory_address);
    println!("Init Code Hash:  {}", init_code_hash);

    match mode {
        MatchMode::LeadingZeros => {
            println!("Mode:            Leading Zeros (automatic)");
        }
        _ => {
            println!(
                "Pattern:         {} ({})",
                cli.pattern.as_ref().unwrap(),
                mode
            );
            println!("Case Sensitive:  {}", cli.case_sensitive);
        }
    }

    println!("Threads:         {}", cli.jobs);
    if cli.max_attempts > 0 {
        println!("Max Attempts:    {}", format_attempts(cli.max_attempts));
    }
    println!("============================\n");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();

    // Auto-detect CPU cores if jobs is 0
    if cli.jobs == 0 {
        cli.jobs = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        println!("🔧 Detected {} CPU cores", cli.jobs);
    }

    // Validate inputs
    validate_inputs(&cli)?;

    let factory_address = cli.factory.parse::<Address>().unwrap();
    let init_code_hash = cli.init_code_hash.parse::<FixedBytes<32>>().unwrap();
    let mode: MatchMode = cli.mode.clone().into();

    print_configuration(&cli, factory_address, init_code_hash);

    let start_time = Instant::now();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let max_leading_zeros = Arc::new(AtomicU8::new(0));

    // Create channel for results
    let (sender, receiver): (Sender<VanityResult>, Receiver<VanityResult>) = unbounded();

    // Start progress reporter
    let progress_counter = Arc::clone(&counter);
    let progress_max_zeros = Arc::clone(&max_leading_zeros);
    let progress_mode = mode.clone();
    let _progress_handle = thread::spawn(move || {
        print_progress(
            progress_counter,
            start_time,
            progress_max_zeros,
            progress_mode,
        );
    });

    // Generate initial random salt nonce and distribute workers across the space
    let mut rng = rand::thread_rng();
    let base_salt_nonce = U256::from_be_bytes(rng.r#gen::<[u8; 32]>());
    let worker_increment = U256::MAX / U256::from(cli.jobs as u64);

    // Start worker threads
    let workers: Vec<_> = (0..cli.jobs)
        .map(|worker_id| {
            let sender = sender.clone();
            let stop_flag = Arc::clone(&stop_flag);
            let counter = Arc::clone(&counter);
            let max_leading_zeros = Arc::clone(&max_leading_zeros);
            let initializer = cli.initializer.clone();
            let pattern = cli.pattern.clone();
            let mode = mode.clone();
            let singleton = cli.singleton.clone().map(|s| s.parse::<Address>().unwrap());
            
            // Each worker starts from a different offset to avoid duplicates
            let starting_salt_nonce = base_salt_nonce.wrapping_add(
                worker_increment.wrapping_mul(U256::from(worker_id as u64))
            );

            thread::spawn(move || {
                worker(
                    factory_address,
                    init_code_hash,
                    initializer,
                    pattern,
                    mode,
                    cli.case_sensitive,
                    sender,
                    stop_flag,
                    counter,
                    singleton,
                    max_leading_zeros,
                    starting_salt_nonce,
                );
            })
        })
        .collect();

    // Drop the original sender so receiver will close when all workers finish
    drop(sender);

    // Handle results based on mode
    match mode {
        MatchMode::LeadingZeros => {
            // Automatic leading zeros mode - keep searching for better results
            while let Ok(result) = receiver.recv() {
                let elapsed = start_time.elapsed();
                let total_attempts = counter.load(Ordering::Relaxed);

                print_result_summary(&result, total_attempts, elapsed);
            }
        }
        _ => {
            // Traditional single-result modes
            let mut result_found = false;
            while let Ok(result) = receiver.recv() {
                stop_flag.store(true, Ordering::Relaxed);
                result_found = true;

                let elapsed = start_time.elapsed();
                let total_attempts = counter.load(Ordering::Relaxed);

                println!("\n🎉 SUCCESS! Found vanity address: {:#x}", result.address);
                print_result_summary(&result, total_attempts, elapsed);
                break;
            }

            // Check max attempts
            if !result_found
                && cli.max_attempts > 0
                && counter.load(Ordering::Relaxed) >= cli.max_attempts
            {
                stop_flag.store(true, Ordering::Relaxed);
                println!(
                    "\n❌ Max attempts ({}) reached without finding a match",
                    format_attempts(cli.max_attempts)
                );
            }

            if !result_found && cli.max_attempts == 0 {
                println!("\n❌ Search interrupted or failed");
            }
        }
    }

    // Wait for all workers to finish
    for worker in workers {
        let _ = worker.join();
    }

    Ok(())
}
