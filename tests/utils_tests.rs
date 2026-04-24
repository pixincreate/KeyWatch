use key_watch::utils::write_to_file;
use std::env::temp_dir;
use std::fs;

#[test]
fn test_write_to_file() {
    let temp_file = temp_dir().join("key_watch_test_output.txt");
    let content = "Temporary content written to file.";
    let path_str = temp_file.to_str().unwrap();

    write_to_file(path_str, content).expect("Failed to write to file");
    let read_back = fs::read_to_string(path_str).expect("Failed to read back");
    assert_eq!(read_back, content, "Content should match");

    fs::remove_file(temp_file).expect("Cleanup");
}

#[test]
fn test_portable_config_loading() {
    use key_watch::detector::initialize_detectors;

    let detectors = initialize_detectors().expect("Should load detectors");
    assert!(!detectors.is_empty(), "Should load at least one detector");
}
