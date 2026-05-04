fn main() {
    if let Err(err) = key_watch::run_cli() {
        eprintln!("Error: {}", err);
        std::process::exit(key_watch::EXIT_CODE_RUNTIME_ERROR);
    }
}
