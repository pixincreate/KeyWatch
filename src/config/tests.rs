mod application;
mod discovery;

use crate::detector::Detector;
use std::io::Write;
use tempfile::TempDir;

fn write_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    path
}

fn minimal_rule_toml(name: &str, pattern: &str, severity: &str) -> String {
    format!(
        "[[rules]]\nname = \"{name}\"\npattern = \"{pattern}\"\nfinding_type = \"Test\"\nseverity = \"{severity}\"\n"
    )
}

fn make_detectors() -> Vec<Detector> {
    vec![Detector::new("ExistingDet", r"\bFOO\b", "Foo", "HIGH", &[], &[], None).unwrap()]
}
