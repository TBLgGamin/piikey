//! Embeds the brand icon and the version information in `piikey-cli.exe`.

include!("app/assets/rc_macros.rs");

fn main() {
    println!("cargo:rerun-if-changed=app/assets/piikey.rc");
    println!("cargo:rerun-if-changed=app/assets/piikey.ico");
    println!("cargo:rerun-if-changed=app/assets/rc_macros.rs");
    let macros = match rc_macros("piikey command line", "piikey-cli.exe") {
        Ok(macros) => macros,
        Err(error) => {
            println!("cargo:warning={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = embed_resource::compile_for("app/assets/piikey.rc", ["piikey-cli"], &macros)
        .manifest_required()
    {
        println!("cargo:warning={error}");
        std::process::exit(1);
    }
}
