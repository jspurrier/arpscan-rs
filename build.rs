use std::path::Path;
use std::fs;
use std::env;

fn main() {
    // Tell Cargo to rerun this script if oui.txt changes
    println!("cargo:rerun-if-changed=src/files/oui.txt");

    // Get the directory containing Cargo.toml
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Source path of oui.txt
    let source = Path::new(&manifest_dir).join("src/files/oui.txt");

    // Determine the target directory based on the build profile (debug or release)
    let profile = env::var("PROFILE").expect("PROFILE not set");
    let target_dir = Path::new(&manifest_dir).join("target").join(profile);
    let dest = target_dir.join("oui.txt");

    // Ensure the target directory exists
    fs::create_dir_all(&target_dir).expect("Failed to create target directory");

    // Copy the file
    if source.exists() {
        fs::copy(&source, &dest).expect("Failed to copy oui.txt to output directory");
        println!("cargo:warning=copied oui.txt to {:?}", dest);
    } else {
        panic!("oui.txt not found in src/files/");
    }
}