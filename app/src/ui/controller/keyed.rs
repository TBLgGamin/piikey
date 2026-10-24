//! What the controller shows of the vault: its values and where they went, the activity feed that
//! remembers it, and removing values.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Weak, mpsc::Receiver},
    time::{Duration, Instant},
};

use piikey::{detect::EntityKind, vault::VaultView};

use super::{Command, Controller, Notice, State};
use crate::{
    Res,
    proxy::Event,
    ui::{
        activity::{self, Activity},
        exports,
    },
};

/// Swaps the Overview page lists as the recent ones.
pub const RECENT: usize = 5;

/// The activity feed is written at most this often while traffic flows, and at shutdown.
const FEED_SAVE_EVERY: Duration = Duration::from_secs(30);

/// Where and when traffic went: the last time a value was sent, or the latest masking/restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub host: String,
    /// The program that sent it, when known.
    pub exe: Option<String>,
    /// When, as a feed shows it: `14:05`, `yesterday 14:05`, `Mon 14:05` or `12 Oct`.
    pub at: String,
}

/// One vault record: a value and the proxy that stands in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyed {
    pub kind: EntityKind,
    pub original: String,
    pub proxy: String,
    /// `None` when it was never sent.
    pub sent: Option<Sent>,
}

/// How far back the Vault page looks, by when a value was last sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Period {
    #[default]
    Any,
    Today,
    Week,
    Month,
}

impl Period {
    pub const ALL: [Self; 4] = [Self::Any, Self::Today, Self::Week, Self::Month];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Any => "Any time",
            Self::Today => "Today",
            Self::Week => "Last 7 days",
            Self::Month => "Last 30 days",
        }
    }

    /// Local days before today a value sent within this period may be; `None` is any.
    const fn days(self) -> Option<i64> {
        match self {
            Self::Any => None,
            Self::Today => Some(0),
            Self::Week => Some(6),
            Self::Month => Some(29),
        }
    }
}

/// What the Vault page asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyedQuery {
    /// Matched, ignoring case, against the value, its stand-in, the site and the program.
    pub text: String,
    pub kind: Option<EntityKind>,
    /// Values last sent to this site or one of its subdomains.
    pub site: Option<String>,
    pub period: Period,
}

/// One page of [`Controller::keyed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyedPage {
    /// Most recently sent first, then the values never sent, newest first.
    pub items: Vec<Keyed>,
    /// Records that match, `items` included.
    pub matched: usize,
    /// Every site a value that is still in the vault went to, most recently first: the site
    /// filter's choices.
    pub sites: Vec<String>,
}

impl KeyedPage {
    /// Counts a match, and keeps it while the page has room for `limit` items.
    fn add(
        &mut self,
        limit: usize,
        kind: EntityKind,
        original: &str,
        proxy: &str,
        sent: Option<Sent>,
    ) {
        self.matched += 1;
        if self.items.len() < limit {
            self.items.push(Keyed {
                kind,
                original: original.to_owned(),
                proxy: proxy.to_owned(),
                sent,
            });
        }
    }
}

/// The vault's part of the Overview page.
#[derive(Default)]
pub(super) struct VaultSummary {
    issued: u64,
    recent: Vec<Keyed>,
}

impl VaultSummary {
    /// Moves the numbers into `state`.
    pub(super) fn apply(self, state: &mut State) {
        state.issued = self.issued;
        state.recent = self.recent;
    }
}

impl Controller {
    /// The values `query` asks for, most recently sent first, then (when no site or period is
    /// asked for) the values never sent, newest first: at most `limit` of them, and how many
    /// match in all.
    pub fn keyed(&self, query: &KeyedQuery, limit: usize) -> KeyedPage {
        self.reading(|view, activity| collect(view, activity, query, limit, true))
            .unwrap_or_default()
    }

    /// Runs `read` on the vault and on the activity feed as it is now; `None` when the vault
    /// cannot be read. The view holds the vault's read lock, which the proxy's writes wait for:
    /// `read` does no more than it must.
    fn reading<R>(&self, read: impl FnOnce(&VaultView<'_>, &Activity) -> R) -> Option<R> {
        // The state first, then the vault: `Shared` is never locked while the state mutex is held.
        let activity = Arc::clone(&self.lock().activity);
        let engine = self.engine();
        let view = engine.vault().read().ok()?;
        Some(read(&view, &activity))
    }

    /// Writes the vault as CSV to a new file in Downloads and returns where it is. The file holds
    /// the values themselves.
    ///
    /// # Errors
    /// A message when the file cannot be written.
    pub fn export_vault(&self) -> Res<PathBuf> {
        exports::vault_csv(&self.engine(), &exports::downloads()?, &exports::stamp())
    }

    /// The vault lost records outside the controller (the API removed them): what was typed may
    /// hold their values, and the numbers of Overview are old.
    pub fn vault_changed(&self) {
        self.shared.typed.clear();
        self.submit(Command::Refresh);
    }

    /// Writes the activity feed when it changed and `now` is set or the last write is
    /// [`FEED_SAVE_EVERY`] ago. It is a convenience: a failed write is retried next time.
    pub(super) fn save_feed(&self, now: bool) {
        let text = {
            let mut state = self.lock();
            if !state.feed_dirty || !(now || state.feed_saved.elapsed() >= FEED_SAVE_EVERY) {
                return;
            }
            state.feed_saved = Instant::now();
            state.feed_dirty = false;
            state.activity.to_text()
        };
        if self.backend.save_activity(&text).is_err() {
            self.lock().feed_dirty = true;
        }
    }

    /// Removes the vault records whose value or stand-in is one of `values`.
    pub(super) fn forget(&self, values: &[String]) {
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        if let Err(error) = self.engine().forget(&values) {
            self.notify(Notice::error(format!(
                "Could not forget the values: {error}"
            )));
        }
        self.vault_lost();
    }

    /// What was typed may hold values the vault no longer knows, and the numbers of Overview are old.
    fn vault_lost(&self) {
        self.shared.typed.clear();
        self.refresh();
    }

    /// Drops what the feed remembers of stand-ins the vault no longer holds. The generator
    /// makes the same stand-in for the same value again, so a value that was forgotten and is
    /// typed anew would otherwise come back with the sites and the count of its old life.
    pub(super) fn prune_activity(&self) {
        let Some(gone) = self.reading(|view, activity| {
            activity
                .iter()
                .filter(|used| view.kind_of(&used.proxy).is_none())
                .map(|used| used.proxy.clone())
                .collect::<HashSet<String>>()
        }) else {
            return;
        };
        if gone.is_empty() {
            return;
        }
        self.update(|state| {
            if Arc::make_mut(&mut state.activity).retain(|used| !gone.contains(&used.proxy)) {
                state.feed_dirty = true;
            }
        });
    }

    /// The vault's numbers for the Overview page, and its list: the most recently sent values, filled
    /// up with the newest records. Takes the state lock briefly, so never call it holding it.
    pub(super) fn vault_summary(&self) -> VaultSummary {
        self.reading(|view, activity| VaultSummary {
            issued: view.record_count(),
            recent: collect(view, activity, &KeyedQuery::default(), RECENT, false).items,
        })
        .unwrap_or_default()
    }

    /// Notes where the proxies of a proxy event went; a failure of the proxy itself also stops
    /// the app.
    pub(super) fn record(&self, event: &Event) {
        let now = activity::now();
        match event {
            Event::Masked {
                host, exe, proxies, ..
            } => {
                self.update(|state| {
                    let activity = Arc::make_mut(&mut state.activity);
                    for proxy in proxies {
                        activity.record(proxy, host, exe.as_deref(), now);
                    }
                    state.feed_dirty = true;
                    state.last_activity = Some(shown(host, exe.as_deref(), now, now));
                });
                // After recording: the Overview list starts with what was just sent.
                let summary = self.vault_summary();
                self.update(|state| summary.apply(state));
            }
            Event::Restored { host, .. } => self.update(|state| {
                state.last_activity = Some(shown(host, None, now, now));
            }),
            Event::Error(reason) => self.submit(Command::Fatal(reason.clone())),
        }
        self.save_feed(false);
    }
}

/// The page `query` asks for, from the stand-ins that were sent (`activity`) and the records of
/// `view`. With `whole` every record is visited, as `matched` and `sites` need it; without, the
/// walk ends as soon as `limit` items are in, and those two are not filled.
fn collect(
    view: &VaultView<'_>,
    activity: &Activity,
    query: &KeyedQuery,
    limit: usize,
    whole: bool,
) -> KeyedPage {
    let now = activity::now();
    let mut needle = Needle::new(&query.text);
    let mut page = KeyedPage::default();
    let full = |page: &KeyedPage| !whole && page.items.len() >= limit;
    let mut sites: HashSet<&str> = HashSet::new();
    for used in activity.iter() {
        if full(&page) {
            return page;
        }
        let (Some(kind), Some(original)) =
            (view.kind_of(&used.proxy), view.original_for(&used.proxy))
        else {
            continue;
        };
        if whole && sites.insert(used.host.as_str()) {
            page.sites.push(used.host.clone());
        }
        let wanted = query.kind.is_none_or(|k| k == kind)
            && query
                .site
                .as_deref()
                .is_none_or(|site| on_site(&used.host, site))
            && query
                .period
                .days()
                .is_none_or(|days| activity::day(now) - activity::day(used.ticks) <= days)
            && (needle.is_empty()
                || needle.is_in(original)
                || needle.is_in(&used.proxy)
                || needle.is_in(&used.host)
                || used.exe.as_deref().is_some_and(|exe| needle.is_in(exe)));
        if wanted {
            let sent = shown(&used.host, used.exe.as_deref(), used.ticks, now);
            page.add(limit, kind, original, &used.proxy, Some(sent));
        }
    }
    if query.site.is_none() && query.period == Period::Any {
        let sent: HashSet<&str> = activity.iter().map(|used| used.proxy.as_str()).collect();
        for (kind, original, proxy) in view.newest_first() {
            if full(&page) {
                break;
            }
            if !sent.contains(proxy)
                && query.kind.is_none_or(|k| k == kind)
                && (needle.is_empty() || needle.is_in(original) || needle.is_in(proxy))
            {
                page.add(limit, kind, original, proxy, None);
            }
        }
    }
    page
}

/// What a search for some text finds, ignoring case. Each string is folded into one buffer that
/// is reused, so a walk over a vault of any size allocates nothing per record.
struct Needle {
    folded: String,
    buffer: String,
}

impl Needle {
    fn new(text: &str) -> Self {
        let mut folded = String::new();
        fold(&mut folded, text.trim());
        Self {
            folded,
            buffer: String::new(),
        }
    }

    /// The search is for nothing: everything matches.
    fn is_empty(&self) -> bool {
        self.folded.is_empty()
    }

    /// Whether `haystack` holds the text.
    fn is_in(&mut self, haystack: &str) -> bool {
        fold(&mut self.buffer, haystack);
        self.buffer.contains(self.folded.as_str())
    }
}

/// Puts `text` in lower case into `into`, which it replaces.
fn fold(into: &mut String, text: &str) {
    into.clear();
    if text.is_ascii() {
        into.push_str(text);
        into.make_ascii_lowercase();
    } else {
        into.extend(text.chars().flat_map(char::to_lowercase));
    }
}

/// Whether `host` is `site` or one of its subdomains.
fn on_site(host: &str, site: &str) -> bool {
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// A send by `exe` to `host` at `ticks`, as a row shows it seen from `now`.
fn shown(host: &str, exe: Option<&str>, ticks: i64, now: i64) -> Sent {
    Sent {
        host: host.to_owned(),
        exe: exe.map(str::to_owned),
        at: activity::when(ticks, now),
    }
}

/// Moves the proxy's events into the controller until the controller goes away.
pub(super) fn pump_events(controller: &Weak<Controller>, events: &Receiver<Event>) {
    while let Ok(event) = events.recv() {
        let Some(controller) = controller.upgrade() else {
            break;
        };
        controller.record(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_ignores_case_in_any_script() {
        let mut needle = Needle::new("  MÜLLER ");
        assert!(needle.is_in("Jürgen Müller"));
        assert!(!needle.is_in("Jurgen Muller"));
        let mut plain = Needle::new("ACME");
        assert!(plain.is_in("jan@Acme.nl"));
        assert!(!plain.is_in("jan@example.org"));
        assert!(Needle::new("   ").is_empty());
    }

    #[test]
    fn a_site_holds_its_subdomains_and_nothing_longer() {
        assert!(on_site("openai.com", "openai.com"));
        assert!(on_site("chat.openai.com", "openai.com"));
        assert!(!on_site("notopenai.com", "openai.com"));
        assert!(!on_site("openai.com", "chat.openai.com"));
    }
}
