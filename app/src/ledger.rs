//! Proxies sent per host: the scope for tolerant restore.
//!
//! Tolerant matching (typos, partial names) is only safe for values this
//! app actually sent to the service whose reply is being restored, so every
//! outgoing request records the proxies it carried here. The ledger lives in
//! memory only: after a restart tolerant restore starts empty, while exact
//! restore keeps working through the vault.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use piikey::{
    restore::{Scope, ScopeEntry},
    vault::Vault,
};

use crate::policy::normalize_host;

/// Proxies remembered per host; the oldest go first.
const PER_HOST_CAP: usize = 5_000;
/// How long a proxy stays in scope after it was last sent.
const TTL: Duration = Duration::from_hours(24);

/// When a proxy was last sent, made unique by a per-host counter so equal
/// instants still order.
type Stamp = (Instant, u64);

/// Sent proxies of one host.
#[derive(Debug, Default)]
struct HostLog {
    /// Proxy -> its latest stamp.
    by_proxy: HashMap<Arc<str>, Stamp>,
    /// Latest stamp -> proxy; oldest first. Mirrors `by_proxy` exactly.
    by_age: BTreeMap<Stamp, Arc<str>>,
    counter: u64,
}

impl HostLog {
    fn touch(&mut self, now: Instant, proxy: &str) {
        self.counter += 1;
        let stamp = (now, self.counter);
        let proxy: Arc<str> = match self.by_proxy.get_key_value(proxy) {
            Some((known, _)) => Arc::clone(known),
            None => Arc::from(proxy),
        };
        if let Some(old) = self.by_proxy.insert(Arc::clone(&proxy), stamp) {
            self.by_age.remove(&old);
        }
        self.by_age.insert(stamp, proxy);
        self.expire(now);
        while self.by_age.len() > PER_HOST_CAP {
            if let Some((_, oldest)) = self.by_age.pop_first() {
                self.by_proxy.remove(&oldest);
            }
        }
    }

    /// Forgets proxies last sent more than [`TTL`] before `now`.
    fn expire(&mut self, now: Instant) {
        while let Some(oldest) = self.by_age.first_entry() {
            if now.saturating_duration_since(oldest.key().0) <= TTL {
                break;
            }
            let proxy = oldest.remove();
            self.by_proxy.remove(&proxy);
        }
    }
}

/// Which proxies each host was sent. Cheap to share (`&self` everywhere).
#[derive(Default)]
pub struct Ledger {
    hosts: Mutex<HashMap<String, HostLog>>,
    /// Bumped by every `touch`, so a cached scope can tell it is stale.
    generation: AtomicU64,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hosts = self.lock().len();
        f.debug_struct("Ledger")
            .field("hosts", &hosts)
            .finish_non_exhaustive()
    }
}

impl Ledger {
    /// Records that `proxy` was sent to `host`.
    pub fn touch(&self, host: &str, proxy: &str) {
        self.touch_at(Instant::now(), host, proxy);
    }

    /// Proxies sent to `host` (and its parent domains) in the last 24 h.
    #[must_use]
    pub fn scope_for(&self, host: &str, vault: &Vault) -> Scope {
        self.scope_at(Instant::now(), host, vault)
    }

    /// The proxies sent to `host` (and its parent domains) in the last 24 h: what a client of
    /// that site may send back as it is.
    #[must_use]
    pub fn sent_to(&self, host: &str) -> HashSet<Arc<str>> {
        self.sent_at(Instant::now(), host).into_iter().collect()
    }

    /// Changes whenever a proxy is recorded.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn touch_at(&self, now: Instant, host: &str, proxy: &str) {
        if proxy.is_empty() {
            return;
        }
        self.lock()
            .entry(normalize_host(host))
            .or_default()
            .touch(now, proxy);
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn scope_at(&self, now: Instant, host: &str, vault: &Vault) -> Scope {
        let sent = self.sent_at(now, host);
        // Proxies the vault does not know (file replaced, or never issued)
        // have nothing to restore to.
        let Ok(view) = vault.read() else {
            return Scope::default();
        };
        Scope::from_pairs(sent.iter().filter_map(|proxy| {
            Some(ScopeEntry {
                kind: view.kind_of(proxy)?,
                proxy: Box::from(&**proxy),
                original: Box::from(view.original_for(proxy)?),
            })
        }))
    }

    /// Distinct proxies sent to `host` or one of its parent domains within
    /// [`TTL`] of `now`, least recently sent first.
    fn sent_at(&self, now: Instant, host: &str) -> Vec<Arc<str>> {
        let host = normalize_host(host);
        let mut latest: HashMap<Arc<str>, Instant> = HashMap::new();
        let mut hosts = self.lock();
        for name in self_and_parents(&host) {
            let Some(log) = hosts.get_mut(name) else {
                continue;
            };
            log.expire(now);
            for (&(sent, _), proxy) in &log.by_age {
                latest
                    .entry(Arc::clone(proxy))
                    .and_modify(|seen| *seen = (*seen).max(sent))
                    .or_insert(sent);
            }
        }
        let mut sent: Vec<_> = latest.into_iter().collect();
        sent.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        sent.into_iter().map(|(proxy, _)| proxy).collect()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, HostLog>> {
        // A panic while holding the lock cannot leave the maps half-updated
        // in a way that matters: both are rebuilt from `touch` calls.
        self.hosts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `a.b.example.com`, `b.example.com`, `example.com`: the host, then every
/// parent that still has two labels. IP addresses have no parents.
fn self_and_parents(host: &str) -> impl Iterator<Item = &str> {
    let parents = host
        .parse::<IpAddr>()
        .is_err()
        .then_some(host)
        .into_iter()
        .flat_map(|host| {
            host.match_indices('.')
                .map(|(dot, _)| &host[dot + 1..])
                .filter(|parent| parent.contains('.'))
        });
    std::iter::once(host).chain(parents)
}

#[cfg(test)]
mod tests {
    use piikey::{detect::EntityKind, engine::Engine};

    use super::*;

    const HOUR: Duration = Duration::from_hours(1);

    fn names(sent: &[Arc<str>]) -> Vec<&str> {
        sent.iter().map(|p| &**p).collect()
    }

    #[test]
    fn touch_then_scope_lists_the_proxy() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "chat.example.com", "p1");
        ledger.touch_at(t0, "other.example.org", "p2");
        assert_eq!(names(&ledger.sent_at(t0, "chat.example.com")), ["p1"]);
        assert_eq!(names(&ledger.sent_at(t0, "other.example.org")), ["p2"]);
        assert!(ledger.sent_at(t0, "unknown.net").is_empty());
    }

    #[test]
    fn host_is_normalized() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "Chat.Example.com:443", "p1");
        assert_eq!(names(&ledger.sent_at(t0, "chat.example.com")), ["p1"]);
        assert_eq!(names(&ledger.sent_at(t0, "CHAT.example.com.")), ["p1"]);
    }

    #[test]
    fn scope_includes_parent_domains_but_not_children_or_siblings() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "example.com", "apex");
        ledger.touch_at(t0, "b.example.com", "mid");
        ledger.touch_at(t0, "a.b.example.com", "leaf");
        ledger.touch_at(t0, "x.example.com", "sibling");
        ledger.touch_at(t0, "com", "tld");
        let sent = ledger.sent_at(t0, "a.b.example.com");
        let mut seen = names(&sent);
        seen.sort_unstable();
        assert_eq!(seen, ["apex", "leaf", "mid"], "no siblings, no bare TLD");
        assert_eq!(names(&ledger.sent_at(t0, "example.com")), ["apex"]);
    }

    #[test]
    fn ip_hosts_have_no_parents() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "0.0.1", "other");
        ledger.touch_at(t0, "127.0.0.1", "mine");
        assert_eq!(names(&ledger.sent_at(t0, "127.0.0.1")), ["mine"]);
    }

    #[test]
    fn proxies_expire_24_hours_after_they_were_last_sent() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "h.com", "old");
        ledger.touch_at(t0 + 23 * HOUR, "h.com", "fresh");
        assert_eq!(
            names(&ledger.sent_at(t0 + 24 * HOUR, "h.com")),
            ["old", "fresh"]
        );
        let later = t0 + 24 * HOUR + Duration::from_secs(1);
        assert_eq!(names(&ledger.sent_at(later, "h.com")), ["fresh"]);
        assert!(ledger.sent_at(t0 + 48 * HOUR, "h.com").is_empty());
    }

    #[test]
    fn sending_a_proxy_again_renews_it() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "h.com", "p");
        ledger.touch_at(t0 + 20 * HOUR, "h.com", "p");
        assert_eq!(names(&ledger.sent_at(t0 + 40 * HOUR, "h.com")), ["p"]);
        assert!(ledger.sent_at(t0 + 45 * HOUR, "h.com").is_empty());
    }

    #[test]
    fn expiry_applies_to_parent_hosts_too() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "example.com", "apex");
        assert!(ledger.sent_at(t0 + 25 * HOUR, "a.example.com").is_empty());
    }

    #[test]
    fn a_host_keeps_only_its_most_recent_5000_proxies() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        for n in 0..PER_HOST_CAP + 3 {
            ledger.touch_at(t0, "h.com", &format!("p{n}"));
        }
        let sent = ledger.sent_at(t0, "h.com");
        assert_eq!(sent.len(), PER_HOST_CAP);
        let all: std::collections::HashSet<&str> = names(&sent).into_iter().collect();
        for gone in ["p0", "p1", "p2"] {
            assert!(!all.contains(gone), "{gone} should have been evicted");
        }
        assert!(all.contains("p3") && all.contains(&*format!("p{}", PER_HOST_CAP + 2)));
        let guard = ledger.lock();
        let log = &guard["h.com"];
        assert_eq!(log.by_proxy.len(), log.by_age.len(), "indexes stay in sync");
    }

    #[test]
    fn re_sent_proxies_do_not_count_twice_against_the_cap() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        for round in 0..3 {
            for n in 0..PER_HOST_CAP {
                ledger.touch_at(t0 + Duration::from_secs(round), "h.com", &format!("p{n}"));
            }
        }
        assert_eq!(ledger.sent_at(t0 + HOUR / 2, "h.com").len(), PER_HOST_CAP);
    }

    #[test]
    fn the_cap_is_per_host() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        for n in 0..PER_HOST_CAP {
            ledger.touch_at(t0, "a.com", &format!("a{n}"));
            ledger.touch_at(t0, "b.com", &format!("b{n}"));
        }
        assert_eq!(ledger.sent_at(t0, "a.com").len(), PER_HOST_CAP);
        assert_eq!(ledger.sent_at(t0, "b.com").len(), PER_HOST_CAP);
    }

    #[test]
    fn same_proxy_under_host_and_parent_is_listed_once() {
        let ledger = Ledger::default();
        let t0 = Instant::now();
        ledger.touch_at(t0, "a.example.com", "p");
        ledger.touch_at(t0 + HOUR, "example.com", "p");
        assert_eq!(names(&ledger.sent_at(t0 + HOUR, "a.example.com")), ["p"]);
    }

    #[test]
    fn empty_proxy_is_ignored_and_generation_tracks_touches() {
        let ledger = Ledger::default();
        let before = ledger.generation();
        ledger.touch("h.com", "");
        assert_eq!(ledger.generation(), before);
        ledger.touch("h.com", "p");
        assert_ne!(ledger.generation(), before);
    }

    #[test]
    fn scope_resolves_originals_and_kinds_through_the_vault() -> piikey::Result<()> {
        let dir = std::env::temp_dir().join(format!("piikey-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let engine = Engine::open(&dir.join("vault.pkv"))?;
        let vault = engine.vault();
        vault.resolve(
            vec![
                (EntityKind::Email, "jan.jansen@acme.nl".into()),
                (EntityKind::Phone, "+31 6 12345678".into()),
            ],
            &|_, _| false,
        )?;
        let (email_proxy, phone_proxy) = {
            let view = vault.read()?;
            (
                view.proxy_for(EntityKind::Email, "jan.jansen@acme.nl")
                    .map(str::to_owned),
                view.proxy_for(EntityKind::Phone, "+31 6 12345678")
                    .map(str::to_owned),
            )
        };
        let (Some(email_proxy), Some(phone_proxy)) = (email_proxy, phone_proxy) else {
            return Err(piikey::Error::Protocol("vault issued no proxy"));
        };

        let ledger = Ledger::default();
        ledger.touch("chat.example.com", &email_proxy);
        ledger.touch("chat.example.com", &phone_proxy);
        ledger.touch("chat.example.com", "never-issued@nowhere.example");
        ledger.touch("other.com", &phone_proxy);

        let scope = ledger.scope_for("chat.example.com", vault);
        let mut got: Vec<_> = scope
            .entries()
            .iter()
            .map(|e| (e.kind, &*e.original, &*e.proxy))
            .collect();
        got.sort_unstable();
        let mut want = vec![
            (EntityKind::Email, "jan.jansen@acme.nl", &*email_proxy),
            (EntityKind::Phone, "+31 6 12345678", &*phone_proxy),
        ];
        want.sort_unstable();
        assert_eq!(
            got, want,
            "unknown proxies are skipped, other hosts excluded"
        );
        assert!(
            ledger
                .scope_for("elsewhere.org", vault)
                .entries()
                .is_empty()
        );
        Ok(())
    }
}
