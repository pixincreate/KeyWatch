# KeyWatch

**KeyWatch** is a secret scanner written in Rust that scans files or directories for secrets such as API keys, passwords, tokens, and more using a set of configurable detectors.

## Features

- Scan a single file or an entire directory recursively.
- Detect secrets including AWS keys, Google API keys, Slack tokens, JWT tokens, SSH keys, passwords, email addresses, IP addresses, and more.
- Generate output in JSON format.
- Write output to the console (with verbose mode) or to a file.

## Project Structure

```txt
KeyWatch/
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── README.md
├── detectors.toml
├── src
│   ├── cli.rs         // CLI definitions using clap.
│   ├── detector.rs    // Defines secret detectors and their regex patterns.
│   ├── lib.rs         // Re-exports modules for integration testing.
│   ├── main.rs        // Entry point for the binary.
│   ├── report.rs      // Produces the JSON report.
│   ├── scanner.rs     // Implements file/directory scanning.
│   └── utils.rs       // Utility functions (e.g. file I/O).
└── tests
    └── integration_tests.rs  // Integration tests.
```

## Key connections

```graph TD
    A[main.rs] --> B[cli.rs]
    A --> C[scanner.rs]
    C --> D[detector.rs]
    D --> E[detectors.toml]
    C --> F[report.rs]
    A --> G[utils.rs]
```

## Usage

### Build the project

To build the project, run:

```sh
cargo build
```

### Run the Scanner

To run the scanner against a file (showing output on the console), use:

```sh
cargo run -- --file ./path/to/your/file --verbose
```

To scan a directory recursively and output the results to a file:

```sh
cargo run -- --dir ./path/to/your/directory --output results.json
```

### Run the Tests

Integration tests are provided in the `/tests` directory. To run all tests, execute:

```sh
cargo test
```

## Adding More Detectors

The secret detectors are defined in [`detectors.toml`](detectors.toml). You can add more detectors or adjust existing ones to widen the scanning scope.

## License

[MIT License](LICENSE)
