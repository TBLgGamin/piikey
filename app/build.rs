//! Stages the Windows App SDK runtime and embeds the brand icon as the icon of `piikey.exe`.

fn main() {
    windows_reactor_setup::as_self_contained();
    if let Err(error) =
        embed_resource::compile_for("assets/piikey.rc", ["piikey"], embed_resource::NONE)
            .manifest_required()
    {
        println!("cargo:warning={error}");
        std::process::exit(1);
    }
}
