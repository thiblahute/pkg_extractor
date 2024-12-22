// src/main.rs
use env_logger::Env;
use log::{debug, error};
use std::{fs::File, io::BufReader, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "pkg-extractor", about = "Extract macOS .pkg files")]
struct Opt {
    #[structopt(parse(from_os_str))]
    pkg_path: PathBuf,

    #[structopt(short = "o", long = "output", parse(from_os_str))]
    output_dir: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    let env = Env::default().filter_or(
        "RUST_LOG",
        if std::env::args().any(|arg| arg == "--debug") {
            "debug"
        } else {
            "info"
        },
    );

    env_logger::init_from_env(env);

    // Parse command line arguments
    let opt = Opt::from_args();

    // Create and run extractor
    debug!("Opening package file: {}", opt.pkg_path.display());
    let file = File::open(&opt.pkg_path)?;
    let reader = BufReader::new(file);

    pkg_extractor::PkgExtractor::new(reader, opt.output_dir).extract()
}
