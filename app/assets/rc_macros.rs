// Shared by build.rs and app/build.rs through `include!`: the PIIKEY_* macros that
// piikey.rc's VERSIONINFO block reads, built from the package version Cargo passes in.

/// `NAME=VALUE` definitions for rc.exe; string values carry their own quotes.
fn rc_macros(description: &str, exe: &str) -> Result<Vec<String>, String> {
    let var = |name: &str| std::env::var(name).map_err(|error| format!("{name}: {error}"));
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    Ok(vec![
        format!("PIIKEY_VERSION_MAJOR={}", var("CARGO_PKG_VERSION_MAJOR")?),
        format!("PIIKEY_VERSION_MINOR={}", var("CARGO_PKG_VERSION_MINOR")?),
        format!("PIIKEY_VERSION_PATCH={}", var("CARGO_PKG_VERSION_PATCH")?),
        format!("PIIKEY_VERSION_STR=\"{}\"", var("CARGO_PKG_VERSION")?),
        format!("PIIKEY_FILE_DESCRIPTION=\"{description}\""),
        format!("PIIKEY_ORIGINAL_NAME=\"{exe}\""),
    ])
}
