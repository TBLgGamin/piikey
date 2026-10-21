//! Vault key material: a random master key wrapped by DPAPI, and the keys
//! derived from it.

use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::{Error, Result, proxy::ProxyKeys, sys};

/// DPAPI entropy: binds the wrapped blob to this purpose and format version.
const DPAPI_ENTROPY: &[u8] = b"piikey vault master key v1";

// blake3 `derive_key` contexts. Changing one orphans every existing vault.
const CONTEXT_RECORDS: &str = "piikey vault v1 record encryption";
const CONTEXT_PROXY_GEN: &str = "piikey vault v1 proxy generation";
const CONTEXT_WATERMARK: &str = "piikey vault v1 proxy watermark";

/// 256-bit master key, wiped on drop.
pub(super) type Master = Zeroizing<[u8; 32]>;

/// Everything derived from the master key.
pub(super) struct VaultKeys {
    /// `XChaCha20-Poly1305` over vault records.
    pub(super) records: XChaCha20Poly1305,
    /// Proxy derivation and watermark keys.
    pub(super) proxy: ProxyKeys,
}

impl VaultKeys {
    pub(super) fn derive(master: &Master) -> Self {
        let derive = |context: &str| Zeroizing::new(blake3::derive_key(context, master.as_slice()));
        let records = derive(CONTEXT_RECORDS);
        let gen_key = derive(CONTEXT_PROXY_GEN);
        let mark_key = derive(CONTEXT_WATERMARK);
        Self {
            records: XChaCha20Poly1305::new(Key::cast_from_core(&records)),
            proxy: ProxyKeys::new(*gen_key, *mark_key),
        }
    }
}

/// A fresh random master key.
pub(super) fn generate_master() -> Result<Master> {
    let mut master = Zeroizing::new([0u8; 32]);
    sys::fill_random(master.as_mut_slice())?;
    Ok(master)
}

/// Wraps `master` so only the current Windows user on this machine can unwrap it.
pub(super) fn wrap(master: &Master) -> Result<Vec<u8>> {
    sys::dpapi_protect(master.as_slice(), DPAPI_ENTROPY)
}

/// Inverse of [`wrap`].
pub(super) fn unwrap(blob: &[u8]) -> Result<Master> {
    let plain = sys::dpapi_unprotect(blob, DPAPI_ENTROPY)?;
    if plain.len() != 32 {
        return Err(Error::Dpapi(
            "unwrapped vault key has the wrong length".into(),
        ));
    }
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&plain);
    Ok(master)
}
