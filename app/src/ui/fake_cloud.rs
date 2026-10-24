//! A pretend cloud account, for demos and screenshots of a debug build. With the environment
//! variable `PIIKEY_FAKE_CLOUD=1` the app has the account `Example cloud` (stored as a Box account,
//! but the window shows the neutral cloud glyph and "Example provider", never a real brand) whose folders
//! are a small fixed tree held in memory, and signing in takes no browser. The files hold only
//! made-up values (`example.net`, `example.org`, documentation phone numbers, well-known test
//! IBANs), and the patterns find all of them without the model.
//!
//! The demo profile's `guard.cfg` adds the location itself:
//! `inventory_root=\\Box\Example cloud\Shared`.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use piikey::{
    inventory::ContentHash,
    sources::{
        self, Account, Accounts, BoxSubject, Changes, Connector, Error, Provider, RemoteFolder,
        RemoteItem, Resolved, SignIn,
    },
    sys,
};

/// The account's name: the share part of its paths.
pub const LABEL: &str = "Example cloud";

/// What the window calls the fake account's provider (see `assets::provider_name`): the account
/// is stored as a Box account, which a demo must not show.
pub const PROVIDER: &str = "Example provider";

/// The environment variable that turns the fake on.
const VARIABLE: &str = "PIIKEY_FAKE_CLOUD";

/// The client id and the client secret the account is made with: nothing reads them.
const CLIENT: &str = "example";

/// Where the pages of the fake files are said to be.
const WEB: &str = "https://example.com/piikey-example-cloud";

/// The cursor that says the listing is up to date: the tree never changes.
const UP_TO_DATE: &str = "1";

/// When the first file was changed (seconds since 1970); each later file a day after the one
/// before.
const FIRST_CHANGED: u64 = 1_741_000_000;

/// A day in seconds.
const DAY: u64 = 86_400;

/// The files, as `/`-separated paths below the account's top, with their contents. The order is
/// the order of the listings; a folder exists while a file is in it.
const FILES: [(&str, &str); 7] = [
    (
        "Shared/Clients/contacts.csv",
        concat!(
            "name,email,phone\n",
            "Anna de Vries,anna.devries@example.net,+31 20 794 0100\n",
            "Bram Jansen,bram.jansen@example.org,+31 20 794 0101\n",
            "Carla Bos,carla.bos@example.net,+31 20 794 0102\n",
            "Daan Visser,daan.visser@example.org,+44 20 7946 0958\n",
            "Eva Smit,eva.smit@example.net,+1 202 555 0143\n",
        ),
    ),
    (
        "Shared/Clients/notes.txt",
        concat!(
            "Notes of the client meeting\n",
            "Contact Anna de Vries at anna.devries@example.net or on +31 20 794 0100.\n",
            "Her colleague Bram can be reached at bram.jansen@example.org.\n",
            "Send the signed contract to Voorbeeldstraat 12, 1011 AB Amsterdam.\n",
        ),
    ),
    (
        "Shared/HR/onboarding.txt",
        concat!(
            "Onboarding checklist for new colleagues\n",
            "The welcome mail goes to sara.mulder@example.net and her manager tim.bakker@example.org.\n",
            "The salary is paid to NL91ABNA0417164300.\n",
            "Expenses are paid to DE89370400440532013000.\n",
        ),
    ),
    (
        "Shared/HR/payroll.csv",
        concat!(
            "employee,iban,email\n",
            "Sara Mulder,NL91ABNA0417164300,sara.mulder@example.net\n",
            "Tim Bakker,GB82WEST12345698765432,tim.bakker@example.org\n",
            "Noor Peters,BE68539007547034,noor.peters@example.net\n",
        ),
    ),
    (
        "Shared/Finance/invoice.eml",
        concat!(
            "From: Finance <accounts@example.net>\r\n",
            "To: Jan Jansen <jan.jansen@example.org>\r\n",
            "Subject: Invoice for March\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Please pay the invoice to NL91ABNA0417164300.\r\n",
            "Questions: accounts@example.net\r\n",
        ),
    ),
    (
        "Shared/readme.txt",
        concat!(
            "Welcome to the shared folder.\n",
            "These files are examples for trying piikey. Nothing in them is real.\n",
        ),
    ),
    (
        "Archive/old/customers.txt",
        concat!(
            "Customers before the move\n",
            "Mail the newsletter to lotte.dekker@example.net, mark.hendriks@example.org and zoe.vermeer@example.net.\n",
        ),
    ),
];

/// Whether this debug build was asked for the fake account.
#[must_use]
pub fn enabled() -> bool {
    std::env::var(VARIABLE).is_ok_and(|value| value == "1")
}

/// Whether `account` is the fake one: a Box account with the fake's name.
#[must_use]
pub fn is_fake(account: &Account) -> bool {
    is_fake_named(account.provider, &account.label)
}

/// Whether the account called `label` of `provider` is the fake one.
#[must_use]
pub fn is_fake_named(provider: Provider, label: &str) -> bool {
    provider == Provider::Box && label == LABEL
}

/// Makes sure the data folder `data` has the fake account when the fake is on, so the window
/// shows it connected. A failure is printed and nothing else: this is a tool of the developer.
pub fn bootstrap(data: &Path) {
    if !enabled() {
        return;
    }
    if let Err(error) = ensure(data) {
        eprintln!("piikey: could not add the fake cloud account: {error}");
    }
}

/// Adds the fake account to `data` unless it is there. Its client secret is what makes it
/// connected.
fn ensure(data: &Path) -> piikey::Result<()> {
    if Accounts::open(data)?.list().iter().any(is_fake) {
        return Ok(());
    }
    sources::add_account(
        data,
        Provider::Box,
        LABEL,
        SignIn::BoxApp {
            client_id: CLIENT.to_owned(),
            subject: BoxSubject::Enterprise("0".to_owned()),
        },
        Some(CLIENT),
    )
    .map(drop)
}

/// What a virtual path of the fake account names.
enum Node {
    /// A folder, as the names from the account's top down; none for the top itself.
    Folder(Vec<&'static str>),
    /// The file at this place of [`FILES`].
    File(usize),
}

/// The fake account's connector: the fixed tree of [`FILES`].
#[derive(Debug)]
pub struct FakeCloud {
    /// The account's name, to know its paths.
    label: String,
    /// The account's top, `\\Box\Example cloud`.
    root: PathBuf,
}

impl FakeCloud {
    /// The connector of `account`, which is the fake account.
    #[must_use]
    pub fn new(account: &Account) -> Self {
        Self {
            label: account.label.clone(),
            root: account.root(),
        }
    }

    /// The virtual path of the folder or file with these names below the top.
    fn path(&self, names: &[&str]) -> PathBuf {
        names
            .iter()
            .fold(self.root.clone(), |path, name| sources::child(&path, name))
    }

    fn folder_at(&self, names: &[&'static str]) -> RemoteFolder {
        RemoteFolder {
            id: format!("folder:{}", names.join("/")),
            path: self.path(names),
            web_url: web(names),
        }
    }

    /// The file at this place of [`FILES`].
    fn item(&self, index: usize) -> Option<RemoteItem> {
        let (name, text) = FILES.get(index)?;
        let names: Vec<&str> = name.split('/').collect();
        Some(RemoteItem {
            id: format!("file:{name}"),
            path: self.path(&names),
            size: u64::try_from(text.len()).unwrap_or(u64::MAX),
            modified: UNIX_EPOCH
                + Duration::from_secs(
                    FIRST_CHANGED + DAY.saturating_mul(u64::try_from(index).unwrap_or(0)),
                ),
            version: ContentHash::of(text.as_bytes()).to_string(),
            web_url: web(&names),
            export: None,
        })
    }

    /// What `path` names, in the letter case [`FILES`] spells it; `None` for anything else,
    /// including another account.
    fn find(&self, path: &Path) -> Option<Node> {
        let found = sources::parse_virtual(path)?;
        if found.provider != Provider::Box || !found.label.eq_ignore_ascii_case(&self.label) {
            return None;
        }
        let wanted: Vec<String> = found
            .rest
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        if wanted.is_empty() {
            return Some(Node::Folder(Vec::new()));
        }
        for (index, &(name, _)) in FILES.iter().enumerate() {
            let names: Vec<&'static str> = name.split('/').collect();
            let Some(head) = names.get(..wanted.len()) else {
                continue;
            };
            if head
                .iter()
                .zip(&wanted)
                .all(|(have, want)| have.eq_ignore_ascii_case(want))
            {
                return Some(if names.len() == wanted.len() {
                    Node::File(index)
                } else {
                    Node::Folder(head.to_vec())
                });
            }
        }
        None
    }
}

/// Where a browser opens the folder or file with these names.
fn web(names: &[&str]) -> String {
    if names.is_empty() {
        WEB.to_owned()
    } else {
        format!("{WEB}/{}", names.join("/"))
    }
}

fn missing() -> Error {
    Error::not_found(Provider::Box, "nothing is there")
}

impl Connector for FakeCloud {
    fn provider(&self) -> Provider {
        Provider::Box
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> sources::Result<Vec<RemoteFolder>> {
        let inside = match under {
            None => Vec::new(),
            Some(folder) => match self.find(&folder.path) {
                Some(Node::Folder(names)) => names,
                _ => return Err(missing()),
            },
        };
        let mut next: Vec<&'static str> = Vec::new();
        for &(path, _) in &FILES {
            let names: Vec<&'static str> = path.split('/').collect();
            // A name below `inside` that has something below it is a folder.
            if names.len() > inside.len() + 1
                && names.starts_with(&inside)
                && let Some(&name) = names.get(inside.len())
                && !next.contains(&name)
            {
                next.push(name);
            }
        }
        Ok(next
            .into_iter()
            .map(|name| {
                let mut names = inside.clone();
                names.push(name);
                self.folder_at(&names)
            })
            .collect())
    }

    fn resolve(&self, path: &Path) -> sources::Result<Resolved> {
        match self.find(path) {
            Some(Node::Folder(names)) => Ok(Resolved::Folder(self.folder_at(&names))),
            Some(Node::File(index)) => self.item(index).map(Resolved::File).ok_or_else(missing),
            None => Err(missing()),
        }
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> sources::Result<Changes> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let up_to_date = cursor == Some(UP_TO_DATE);
        let items = if up_to_date {
            Vec::new()
        } else {
            (0..FILES.len())
                .filter_map(|index| self.item(index))
                .filter(|item| sys::is_under(&item.path, &root.path))
                .collect()
        };
        Ok(Changes {
            items,
            removed: Vec::new(),
            cursor: UP_TO_DATE.to_owned(),
            full: !up_to_date,
        })
    }

    fn download(
        &self,
        item: &RemoteItem,
        max: u64,
        cancel: &AtomicBool,
    ) -> sources::Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let Some(Node::File(index)) = self.find(&item.path) else {
            return Err(missing());
        };
        let (_, text) = FILES.get(index).ok_or_else(missing)?;
        if u64::try_from(text.len()).is_ok_and(|len| len > max) {
            return Err(Error::TooLarge);
        }
        Ok(text.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        error::Error as StdError,
        sync::{Mutex, PoisonError},
    };

    use piikey::{
        detect::EntityKind::{self, Email, Iban, Phone},
        engine::Engine,
        formats::{self, Report},
        sources::TokenStore,
    };

    use super::*;
    use crate::ui::testing::temp_dir;

    type Res = Result<(), Box<dyn StdError>>;

    fn account(provider: Provider, label: &str) -> Account {
        Account {
            id: "0123456789abcdef".to_owned(),
            provider,
            label: label.to_owned(),
            sign_in: SignIn::BoxApp {
                client_id: CLIENT.to_owned(),
                subject: BoxSubject::Enterprise("0".to_owned()),
            },
        }
    }

    fn fake() -> FakeCloud {
        FakeCloud::new(&account(Provider::Box, LABEL))
    }

    /// The names (last part of the path) of `folders`.
    fn leaves(folders: &[RemoteFolder]) -> Vec<String> {
        folders
            .iter()
            .filter_map(|folder| folder.path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect()
    }

    /// How many values of each type `found` holds, in the order of the types.
    fn counts(found: &[(EntityKind, impl Sized)]) -> Vec<(EntityKind, usize)> {
        let mut by_kind: BTreeMap<EntityKind, usize> = BTreeMap::new();
        for (kind, _) in found {
            *by_kind.entry(*kind).or_default() += 1;
        }
        by_kind.into_iter().collect()
    }

    #[test]
    fn the_top_holds_shared_and_archive_and_shared_its_folders() -> Res {
        let cloud = fake();
        let top = cloud.browse(None)?;
        assert_eq!(leaves(&top), ["Shared", "Archive"]);
        assert_eq!(
            top.iter()
                .map(|folder| folder.path.clone())
                .collect::<Vec<_>>(),
            [
                PathBuf::from(r"\\Box\Example cloud\Shared"),
                PathBuf::from(r"\\Box\Example cloud\Archive"),
            ]
        );
        assert!(top.iter().all(|folder| folder.web_url.starts_with(WEB)));

        let shared = cloud.browse(Some(&cloud.folder_at(&["Shared"])))?;
        assert_eq!(leaves(&shared), ["Clients", "HR", "Finance"]);
        let old = cloud.browse(Some(&cloud.folder_at(&["Archive"])))?;
        assert_eq!(leaves(&old), ["old"]);
        let none = cloud.browse(Some(&cloud.folder_at(&["Shared", "HR"])))?;
        assert!(none.is_empty(), "a folder of files only has no folders");

        let by_helper = sources::browse(&cloud, Some(&cloud.root))?;
        assert_eq!(leaves(&by_helper), ["Shared", "Archive"]);
        let inside = sources::browse(&cloud, Some(Path::new(r"\\Box\Example cloud\shared")))?;
        assert_eq!(leaves(&inside), ["Clients", "HR", "Finance"]);
        assert!(matches!(
            sources::browse(&cloud, Some(Path::new(r"\\Box\Example cloud\Nowhere"))),
            Err(Error::NotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_first_listing_is_full_and_the_next_one_with_its_cursor_is_empty() -> Res {
        let cloud = fake();
        let cancel = AtomicBool::new(false);
        let root = cloud.folder(&cloud.root)?;
        let first = cloud.changes(&root, None, &cancel)?;
        assert!(first.full);
        assert_eq!(first.cursor, UP_TO_DATE);
        assert!(first.removed.is_empty());
        let paths: Vec<PathBuf> = first.items.iter().map(|item| item.path.clone()).collect();
        let expected: Vec<PathBuf> = FILES
            .iter()
            .map(|(name, _)| {
                name.split('/')
                    .fold(cloud.root.clone(), |path, part| sources::child(&path, part))
            })
            .collect();
        assert_eq!(paths, expected);
        for (item, (name, text)) in first.items.iter().zip(&FILES) {
            assert_eq!(item.size, u64::try_from(text.len())?);
            assert_eq!(item.web_url, format!("{WEB}/{name}"));
            assert_eq!(item.export, None);
            assert_eq!(item.version.len(), 32, "a content hash");
        }
        let mut versions: Vec<&str> = first.items.iter().map(|i| i.version.as_str()).collect();
        versions.sort_unstable();
        versions.dedup();
        assert_eq!(
            versions.len(),
            FILES.len(),
            "every file has its own version"
        );
        assert_eq!(
            first,
            cloud.changes(&root, None, &cancel)?,
            "a listing is stable"
        );

        let next = cloud.changes(&root, Some(&first.cursor), &cancel)?;
        assert!(!next.full);
        assert!(next.items.is_empty() && next.removed.is_empty());
        assert_eq!(next.cursor, UP_TO_DATE);

        let unknown = cloud.changes(&root, Some("a cursor from elsewhere"), &cancel)?;
        assert!(unknown.full);
        assert_eq!(unknown.items.len(), FILES.len());

        let shared = cloud.changes(&cloud.folder_at(&["Shared"]), None, &cancel)?;
        assert_eq!(shared.items.len(), 6);
        let archive = cloud.changes(&cloud.folder_at(&["Archive"]), None, &cancel)?;
        assert_eq!(archive.items.len(), 1);

        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(
            cloud.changes(&root, None, &cancel),
            Err(Error::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn resolve_finds_folders_and_files_in_any_letter_case_and_nothing_else() -> Res {
        let cloud = fake();
        let file = cloud.file(Path::new(
            r"\\Box\Example cloud\Shared\clients\CONTACTS.csv",
        ))?;
        assert_eq!(file.id, "file:Shared/Clients/contacts.csv");
        assert_eq!(
            cloud
                .folder(Path::new(r"\\box\example cloud\Shared\HR"))?
                .id,
            "folder:Shared/HR"
        );
        assert_eq!(cloud.folder(&cloud.root)?.web_url, WEB);
        assert!(cloud.folder(&file.path).is_err(), "a file is no folder");
        assert!(
            cloud
                .file(Path::new(r"\\Box\Example cloud\Shared"))
                .is_err(),
            "a folder is no file"
        );
        for gone in [
            r"\\Box\Example cloud\Shared\missing.txt",
            r"\\Box\Other cloud\Shared\readme.txt",
            r"\\Dropbox\Example cloud\Shared\readme.txt",
            r"C:\Shared\readme.txt",
        ] {
            assert!(
                matches!(cloud.resolve(Path::new(gone)), Err(Error::NotFound { .. })),
                "{gone}"
            );
        }
        Ok(())
    }

    #[test]
    fn download_gives_each_file_its_bytes_and_honours_the_limit_and_cancel() -> Res {
        let cloud = fake();
        let cancel = AtomicBool::new(false);
        let root = cloud.folder(&cloud.root)?;
        let listing = cloud.changes(&root, None, &cancel)?;
        for (item, (_, text)) in listing.items.iter().zip(&FILES) {
            assert_eq!(cloud.download(item, u64::MAX, &cancel)?, text.as_bytes());
            assert!(matches!(
                cloud.download(item, item.size - 1, &cancel),
                Err(Error::TooLarge)
            ));
            assert_eq!(
                cloud.download(item, item.size, &cancel)?.len(),
                text.len(),
                "exactly the limit still fits"
            );
        }
        let first = listing.items.first().ok_or("no items")?;
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(
            cloud.download(first, u64::MAX, &cancel),
            Err(Error::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn the_patterns_find_every_value_of_every_file_and_the_readme_none() -> Res {
        let dir = temp_dir("fake-cloud-scan");
        let engine = Engine::open(&dir.join("vault.pkv"))?;
        let cloud = fake();
        let cancel = AtomicBool::new(false);
        let expected: [(&str, Vec<(EntityKind, usize)>); 7] = [
            ("contacts.csv", vec![(Email, 5), (Phone, 5)]),
            ("notes.txt", vec![(Email, 2), (Phone, 1)]),
            ("onboarding.txt", vec![(Email, 2), (Iban, 2)]),
            ("payroll.csv", vec![(Email, 3), (Iban, 3)]),
            ("invoice.eml", vec![(Email, 3), (Iban, 1)]),
            ("readme.txt", vec![]),
            ("customers.txt", vec![(Email, 3)]),
        ];
        let root = cloud.folder(&cloud.root)?;
        let listing = cloud.changes(&root, None, &cancel)?;
        assert_eq!(listing.items.len(), expected.len());
        for (item, (name, want)) in listing.items.iter().zip(&expected) {
            assert_eq!(
                item.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
                Some((*name).to_owned())
            );
            let bytes = cloud.download(item, u64::MAX, &cancel)?;
            let scanned = formats::scan(&engine, &bytes, false)?;
            assert_eq!(&counts(&scanned.found), want, "{name}");
        }
        Ok(())
    }

    #[test]
    fn a_read_of_the_findings_reports_what_the_scan_counts() -> Res {
        let dir = temp_dir("fake-cloud-findings");
        let engine = Engine::open(&dir.join("vault.pkv"))?;
        let cloud = fake();
        let path = cloud.path(&["Shared", "HR", "payroll.csv"]);
        let seen: Mutex<Vec<EntityKind>> = Mutex::new(Vec::new());
        sources::findings(&cloud, &engine, &path, &AtomicBool::new(false), &|report| {
            if let Report::Found(values) = report {
                seen.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(values.iter().map(|value| value.kind));
            }
            true
        })?;
        let seen = seen.into_inner().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            counts(&seen.iter().map(|kind| (*kind, ())).collect::<Vec<_>>()),
            [(Email, 3), (Iban, 3)]
        );
        Ok(())
    }

    #[test]
    fn only_the_box_account_of_that_name_is_the_fake() {
        assert!(is_fake(&account(Provider::Box, LABEL)));
        assert!(!is_fake(&account(Provider::Box, "Work")));
        assert!(!is_fake(&account(Provider::Dropbox, LABEL)));
        assert!(!is_fake(&account(Provider::GoogleDrive, LABEL)));
    }

    #[test]
    fn the_account_is_added_once_and_is_connected() -> Res {
        let dir = temp_dir("fake-cloud-account");
        ensure(&dir)?;
        ensure(&dir)?;
        let accounts = Accounts::open(&dir)?;
        let [account] = accounts.list() else {
            return Err("expected exactly one account".into());
        };
        assert!(is_fake(account));
        assert_eq!(account.root(), PathBuf::from(r"\\Box\Example cloud"));
        assert!(account.is_connected(&TokenStore::new(&dir))?);
        Ok(())
    }
}
