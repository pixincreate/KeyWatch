pub mod cli;
pub mod detector;
pub mod hooks;
pub mod report;
pub mod scanner;
pub mod utils;

pub use hooks::{generate_pre_commit_hook, generate_pre_push_hook};
