//! Embeds the brand icon as the icon of `piikey-cli.exe`.

fn main() {
    println!("cargo:rerun-if-changed=app/assets/piikey.rc");
    println!("cargo:rerun-if-changed=app/assets/piikey.ico");
    if let Err(error) =
        embed_resource::compile_for("app/assets/piikey.rc", ["piikey-cli"], embed_resource::NONE)
            .manifest_required()
    {
        println!("cargo:warning={error}");
        std::process::exit(1);
    }
}
