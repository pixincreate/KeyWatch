fn main() {
    match key_watch::run_cli() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(key_watch::EXIT_CODE_RUNTIME_ERROR);
        }
    }
}
