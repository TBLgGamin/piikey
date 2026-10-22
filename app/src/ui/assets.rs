//! The brand: the embedded icon file, the logo images per theme and the Windows theme probe.

use std::{
    fs,
    path::{Path, PathBuf},
};

use windows_reactor::{EncodedImage, WindowTheme};
use winreg::{RegKey, enums::HKEY_CURRENT_USER};

use crate::{Describe, Res};

/// `assets/piikey.ico`: the app icon (white key on the purple tile) at 16 to 256 px.
const ICON: &[u8] = include_bytes!("../../assets/piikey.ico");
/// `assets/tray-off.ico`: the key alone in grey, the tray icon while piikey is off.
const TRAY_OFF: &[u8] = include_bytes!("../../assets/tray-off.ico");
/// `assets/tray-attention.ico`: the app icon with an amber dot, the tray icon while piikey needs
/// the user.
const TRAY_ATTENTION: &[u8] = include_bytes!("../../assets/tray-attention.ico");

/// The brand kit lives in `assets/brand/piikey-logo-kit` at the repo root; `mono-6f49b1` is the
/// light-mode colour, `mono-d6c9f9` the dark-mode colour.
macro_rules! kit {
    ($path:literal) => {
        include_bytes!(concat!("../../../assets/brand/piikey-logo-kit/", $path))
    };
}

const SYMBOL_LIGHT: &[u8] = kit!("symbol/piikey-symbol-mono-6f49b1.svg");
const SYMBOL_DARK: &[u8] = kit!("symbol/piikey-symbol-mono-d6c9f9.svg");
const LOCKUP_LIGHT: &[u8] = kit!("horizontal/piikey-horizontal-mono-6f49b1.svg");
const LOCKUP_DARK: &[u8] = kit!("horizontal/piikey-horizontal-mono-d6c9f9.svg");
const STACKED_LIGHT: &[u8] = kit!("stacked/piikey-stacked-mono-6f49b1.svg");
const STACKED_DARK: &[u8] = kit!("stacked/piikey-stacked-mono-d6c9f9.svg");

/// The Windows setting that holds the app theme.
const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

fn themed(dark: bool, light_svg: &'static [u8], dark_svg: &'static [u8]) -> EncodedImage {
    EncodedImage::from_static(if dark { dark_svg } else { light_svg })
}

/// The symbol (p-shaped key) in the brand colour for the theme: `#6f49b1` on light, `#d6c9f9` on
/// dark.
#[must_use]
pub fn symbol(dark: bool) -> EncodedImage {
    themed(dark, SYMBOL_LIGHT, SYMBOL_DARK)
}

/// The horizontal lockup (symbol and wordmark) in the brand colour for the theme.
#[must_use]
pub fn lockup(dark: bool) -> EncodedImage {
    themed(dark, LOCKUP_LIGHT, LOCKUP_DARK)
}

/// The stacked lockup (symbol above the wordmark) in the brand colour for the theme.
#[must_use]
pub fn stacked(dark: bool) -> EncodedImage {
    themed(dark, STACKED_LIGHT, STACKED_DARK)
}

/// Whether Windows apps use the dark theme now (`AppsUseLightTheme` is 0). Cheap, so it can be
/// polled; light when the setting is missing. A debug build obeys `PIIKEY_THEME` first.
#[must_use]
pub fn system_dark() -> bool {
    #[cfg(debug_assertions)]
    if let Some(dark) = forced_dark() {
        return dark;
    }
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PERSONALIZE)
        .and_then(|key| key.get_value::<u32, _>("AppsUseLightTheme"))
        .is_ok_and(|light| light == 0)
}

/// The theme the window asks `WinUI` for: the Windows setting. A debug build obeys
/// `PIIKEY_THEME` first.
#[must_use]
pub fn window_theme() -> WindowTheme {
    #[cfg(debug_assertions)]
    if let Some(dark) = forced_dark() {
        return if dark {
            WindowTheme::Dark
        } else {
            WindowTheme::Light
        };
    }
    WindowTheme::System
}

/// Debug builds only, so the README screenshots need no change to the Windows theme:
/// `PIIKEY_THEME=light` or `dark` replaces the Windows setting for this process.
#[cfg(debug_assertions)]
fn forced_dark() -> Option<bool> {
    let value = std::env::var("PIIKEY_THEME").ok()?;
    match value.to_ascii_lowercase().as_str() {
        "light" => Some(false),
        "dark" => Some(true),
        _ => None,
    }
}

/// What the tray icon says at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayIcon {
    /// piikey is off: the key alone, in grey.
    Off,
    /// piikey is on: the app icon.
    On,
    /// piikey needs the user (a missing certificate, a model that failed): the app icon with an
    /// amber dot.
    Attention,
}

impl TrayIcon {
    /// The file's name and contents. The file of `On` is the app icon, which the Explorer verb
    /// and the window use too.
    const fn file(self) -> (&'static str, &'static [u8]) {
        match self {
            Self::Off => ("tray-off.ico", TRAY_OFF),
            Self::On => (ICON_FILE, ICON),
            Self::Attention => ("tray-attention.ico", TRAY_ATTENTION),
        }
    }
}

/// The app icon's file name in the data folder.
const ICON_FILE: &str = "piikey.ico";

/// Writes `bytes` as `name` in `folder` unless the file already holds them, and returns its path.
fn write_icon(folder: &Path, name: &str, bytes: &[u8]) -> Res<PathBuf> {
    let path = folder.join(name);
    if fs::read(&path).is_ok_and(|current| current == bytes) {
        return Ok(path);
    }
    fs::write(&path, bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    Ok(path)
}

/// Writes the icon into the folder of `vault` and returns its path: the tray and the window load
/// icons from files, and the exe stays self-contained this way.
///
/// # Errors
/// The folder is not writable.
pub fn icon_file(vault: &Path) -> Res<PathBuf> {
    let folder = vault.parent().ok_or("the vault path has no folder")?;
    write_icon(folder, ICON_FILE, ICON)
}

/// Writes the tray icon for `state` into the data folder, next to [`icon_file`]'s, and returns
/// its path.
///
/// # Errors
/// The data folder cannot be found or is not writable.
pub fn tray_icon(state: TrayIcon) -> Res<PathBuf> {
    let folder = piikey::sys::data_dir().describe()?;
    tray_icon_in(&folder, state)
}

fn tray_icon_in(folder: &Path, state: TrayIcon) -> Res<PathBuf> {
    let (name, bytes) = state.file();
    write_icon(folder, name, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Widths of the images listed in the ICONDIR of `icon` (a stored 0 means 256).
    fn sizes_of(icon: &[u8]) -> Vec<u32> {
        let count = usize::from(u16::from_le_bytes([icon[4], icon[5]]));
        (0..count)
            .map(|index| match icon[6 + index * 16] {
                0 => 256,
                width => u32::from(width),
            })
            .collect()
    }

    fn icon_sizes() -> Vec<u32> {
        sizes_of(ICON)
    }

    #[test]
    fn the_embedded_icon_is_an_ico_with_every_shell_size() {
        // ICONDIR: reserved 0, type 1 (icon), then the image count.
        assert_eq!(&ICON[..4], &[0, 0, 1, 0]);
        assert_eq!(icon_sizes(), [16, 20, 24, 32, 40, 48, 64, 256]);
    }

    #[test]
    fn every_tray_icon_is_an_ico_with_the_tray_sizes_and_they_differ() {
        let states = [TrayIcon::Off, TrayIcon::On, TrayIcon::Attention];
        for state in states {
            let (name, bytes) = state.file();
            assert_eq!(&bytes[..4], &[0, 0, 1, 0], "{name} is no ico");
            let sizes = sizes_of(bytes);
            for wanted in [16, 20, 24, 32] {
                assert!(sizes.contains(&wanted), "{name} has no {wanted} px image");
            }
        }
        assert_eq!(TrayIcon::On.file().1, ICON, "on is the app icon");
        assert_ne!(TrayIcon::Off.file().1, ICON);
        assert_ne!(TrayIcon::Attention.file().1, ICON);
        assert_ne!(TrayIcon::Off.file().1, TrayIcon::Attention.file().1);
    }

    #[test]
    fn each_tray_icon_is_written_beside_the_app_icon_and_repaired_when_stale() -> Result<(), String>
    {
        let folder = std::env::temp_dir().join(format!("piikey-tray-{}", std::process::id()));
        fs::create_dir_all(&folder).describe()?;
        let mut paths = Vec::new();
        for state in [TrayIcon::Off, TrayIcon::On, TrayIcon::Attention] {
            let path = tray_icon_in(&folder, state)?;
            assert_eq!(path.parent(), Some(folder.as_path()));
            assert_eq!(fs::read(&path).describe()?, state.file().1);
            fs::write(&path, b"stale").describe()?;
            assert_eq!(tray_icon_in(&folder, state)?, path);
            assert_eq!(fs::read(&path).describe()?, state.file().1);
            paths.push(path);
        }
        // One file per state, and the file of `On` is the one `icon_file` writes.
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), 3);
        assert_eq!(
            tray_icon_in(&folder, TrayIcon::On)?,
            icon_file(&folder.join("vault.pkv"))?
        );
        fs::remove_dir_all(&folder).describe()
    }

    #[test]
    fn every_logo_is_an_svg_in_the_colour_of_its_theme() {
        let logos = [
            ("symbol", symbol(false), symbol(true)),
            ("lockup", lockup(false), lockup(true)),
            ("stacked", stacked(false), stacked(true)),
        ];
        for (name, light, dark) in logos {
            let light = String::from_utf8_lossy(light.as_bytes());
            let dark = String::from_utf8_lossy(dark.as_bytes());
            assert!(light.starts_with("<svg"), "{name} light is not an svg");
            assert!(dark.starts_with("<svg"), "{name} dark is not an svg");
            assert!(light.contains("#6f49b1"), "{name} light is not purple");
            assert!(dark.contains("#d6c9f9"), "{name} dark is not lilac");
            assert!(
                !light.contains("#d6c9f9"),
                "{name} light has the dark colour"
            );
            assert!(
                !dark.contains("#6f49b1"),
                "{name} dark has the light colour"
            );
        }
    }

    #[test]
    fn the_icon_is_written_next_to_the_vault_and_repaired_when_stale() -> Result<(), String> {
        let folder = std::env::temp_dir().join(format!("piikey-icon-{}", std::process::id()));
        fs::create_dir_all(&folder).describe()?;
        let vault = folder.join("vault.pkv");

        let path = icon_file(&vault)?;
        assert_eq!(path, folder.join("piikey.ico"));
        assert_eq!(fs::read(&path).describe()?, ICON);

        fs::write(&path, b"stale").describe()?;
        icon_file(&vault)?;
        assert_eq!(fs::read(&path).describe()?, ICON);

        fs::remove_dir_all(&folder).describe()
    }
}
