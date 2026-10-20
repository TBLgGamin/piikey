//! Stages the Windows App SDK runtime and embeds the brand icon and the version information in
//! `piikey.exe`.

include!("assets/rc_macros.rs");

fn main() {
    windows_reactor_setup::as_self_contained();
    println!("cargo:rerun-if-changed=assets/rc_macros.rs");
    println!("cargo:rerun-if-changed=assets/piikey.rc");
    println!("cargo:rerun-if-changed=assets/piikey.ico");
    let macros = match rc_macros("piikey", "piikey.exe") {
        Ok(macros) => macros,
        Err(error) => {
            println!("cargo:warning={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) =
        embed_resource::compile_for("assets/piikey.rc", ["piikey"], &macros).manifest_required()
    {
        println!("cargo:warning={error}");
        std::process::exit(1);
    }
}
