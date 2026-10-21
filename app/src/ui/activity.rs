//! Which stand-ins went where and when, for the activity feed. Kept in
//! `%LOCALAPPDATA%\piikey\activity.cfg`, one line per stand-in, most recently sent first:
//! `<ticks>\t<count>\t<host>\t<exe or ->\t<stand-in>`. `<ticks>` is local Windows file time (100 ns
//! since 1601-01-01). Only stand-ins are kept here; the values they stand for stay in the
//! encrypted vault.

use std::fmt::Write;

use windows_reactor::DateTime;

/// Stand-ins kept; the ones sent longest ago go first.
const CAP: usize = 2000;
/// Windows file time ticks (100 ns) in a day.
const TICKS_PER_DAY: i64 = 864_000_000_000;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// 1601-01-01, day 0, was a Monday.
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Now, as local Windows file time.
pub fn now() -> i64 {
    DateTime::now().to_local().ticks()
}

/// The last time a stand-in was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    pub proxy: String,
    pub host: String,
    /// The program that sent it, when known.
    pub exe: Option<String>,
    pub ticks: i64,
    /// Times it was sent.
    pub count: u32,
}

/// Every stand-in sent, most recently sent first, each once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activity {
    uses: Vec<Use>,
}

impl Activity {
    /// `proxy` was sent to `host` at `ticks`: it moves to the front. What the file could not hold
    /// is not kept.
    pub fn record(&mut self, proxy: &str, host: &str, exe: Option<&str>, ticks: i64) {
        if !keepable(proxy, host, exe) {
            return;
        }
        let count = match self.uses.iter().position(|u| u.proxy == proxy) {
            Some(at) => self.uses.remove(at).count.saturating_add(1),
            None => 1,
        };
        self.uses.insert(
            0,
            Use {
                proxy: proxy.to_owned(),
                host: host.to_owned(),
                exe: exe.map(str::to_owned),
                ticks,
                count,
            },
        );
        self.uses.truncate(CAP);
    }

    /// Most recently sent first.
    pub fn iter(&self) -> impl Iterator<Item = &Use> {
        self.uses.iter()
    }

    /// Forgets the stand-ins `keep` says no to; whether there were any.
    pub fn retain(&mut self, keep: impl FnMut(&Use) -> bool) -> bool {
        let before = self.uses.len();
        self.uses.retain(keep);
        self.uses.len() != before
    }

    /// Reads the file text; lines that do not parse are skipped.
    pub fn parse(text: &str) -> Self {
        let uses = text
            .lines()
            .filter_map(|line| {
                let mut fields = line.split('\t');
                let ticks = fields.next()?.parse().ok()?;
                let count = fields.next()?.parse().ok()?;
                let host = fields.next()?;
                let exe = Some(fields.next()?).filter(|&exe| exe != "-");
                let proxy = fields.next()?;
                if fields.next().is_some() || !keepable(proxy, host, exe) {
                    return None;
                }
                Some(Use {
                    proxy: proxy.to_owned(),
                    host: host.to_owned(),
                    exe: exe.map(str::to_owned),
                    ticks,
                    count,
                })
            })
            .take(CAP)
            .collect();
        Self { uses }
    }

    /// The file text.
    pub fn to_text(&self) -> String {
        self.uses.iter().fold(String::new(), |mut text, u| {
            // Writing to a String cannot fail.
            let _ = writeln!(
                text,
                "{}\t{}\t{}\t{}\t{}",
                u.ticks,
                u.count,
                u.host,
                u.exe.as_deref().unwrap_or("-"),
                u.proxy
            );
            text
        })
    }
}

/// Whether a send of `proxy` to `host` by `exe` can be kept: a field holds no tab or line break,
/// which would break the line, and the file has no line without a stand-in or a site, which
/// [`Activity::parse`] would drop at the next start.
fn keepable(proxy: &str, host: &str, exe: Option<&str>) -> bool {
    !proxy.is_empty()
        && !host.is_empty()
        && [Some(proxy), Some(host), exe]
            .iter()
            .flatten()
            .all(|field| !field.contains(['\t', '\r', '\n']))
}

/// The local day of `ticks`.
pub fn day(ticks: i64) -> i64 {
    ticks.div_euclid(TICKS_PER_DAY)
}

/// When `ticks` was, seen from `now`: `14:05`, `yesterday 14:05`, `Mon 14:05` or `12 Oct`.
pub fn when(ticks: i64, now: i64) -> String {
    let at = DateTime::from_ticks(ticks);
    let clock = format!("{:02}:{:02}", at.hour(), at.minute());
    let days_ago = day(now) - day(ticks);
    match days_ago {
        ..=0 => clock,
        1 => format!("yesterday {clock}"),
        2..=6 => {
            let weekday = WEEKDAYS[usize::try_from(day(ticks).rem_euclid(7)).unwrap_or(0)];
            format!("{weekday} {clock}")
        }
        _ => {
            let month = MONTHS
                .get(usize::try_from(at.month()).unwrap_or(1).saturating_sub(1))
                .copied()
                .unwrap_or("");
            format!("{} {month}", at.day())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-20 (a Tuesday) at 14:05, as file time.
    fn tuesday() -> i64 {
        DateTime::from_unix_secs(1_792_454_400 + 14 * 3600 + 5 * 60).ticks()
    }

    #[test]
    fn sending_again_moves_a_stand_in_to_the_front_and_counts_it() {
        let mut activity = Activity::default();
        activity.record("Bram de Bouwman", "chatgpt.com", Some("chrome.exe"), 1);
        activity.record("floris@cedarforge.nl", "claude.ai", None, 2);
        activity.record("Bram de Bouwman", "claude.ai", None, 3);
        let first = activity.iter().next().ok_or("empty");
        assert_eq!(
            first.map(|u| (u.proxy.as_str(), u.host.as_str(), u.count, u.ticks)),
            Ok(("Bram de Bouwman", "claude.ai", 2, 3))
        );
        assert_eq!(activity.iter().count(), 2);
    }

    #[test]
    fn the_oldest_uses_go_beyond_the_cap() {
        let mut activity = Activity::default();
        for i in 0..CAP + 5 {
            activity.record(
                &format!("p{i}"),
                "a.com",
                None,
                i64::try_from(i).unwrap_or(0),
            );
        }
        assert_eq!(activity.iter().count(), CAP);
        assert!(!activity.iter().any(|u| u.proxy == "p0"));
        assert!(activity.iter().any(|u| u.proxy == format!("p{}", CAP + 4)));
    }

    #[test]
    fn the_file_round_trips_and_bad_lines_are_skipped() {
        let mut activity = Activity::default();
        activity.record("Bram de Bouwman", "chatgpt.com", Some("chrome.exe"), 10);
        activity.record("NL20INGB0001234567", "claude.ai", None, 20);
        let text = format!("garbage\n1\tx\thost\t-\tp\n{}", activity.to_text());
        assert_eq!(Activity::parse(&text), activity);
    }

    #[test]
    fn values_that_would_break_the_file_are_not_kept() {
        let mut activity = Activity::default();
        activity.record("tab\there", "a.com", None, 1);
        activity.record("p", "a.com", Some("line\nbreak"), 1);
        assert_eq!(activity.iter().count(), 0);
    }

    #[test]
    fn what_the_file_would_lose_is_not_kept() {
        // `parse` drops a line without a site or a stand-in: what the feed showed would be gone
        // at the next start.
        let mut activity = Activity::default();
        activity.record("p", "", None, 1);
        activity.record("", "a.com", None, 1);
        assert_eq!(activity.iter().count(), 0);
    }

    #[test]
    fn what_the_vault_lost_leaves_the_feed() {
        let mut activity = Activity::default();
        activity.record("kept", "a.com", None, 1);
        activity.record("lost", "b.com", None, 2);
        assert!(activity.retain(|u| u.proxy != "lost"));
        assert!(
            !activity.retain(|u| u.proxy != "lost"),
            "nothing is left to drop"
        );
        let proxies: Vec<&str> = activity.iter().map(|u| u.proxy.as_str()).collect();
        assert_eq!(proxies, ["kept"]);
    }

    #[test]
    fn times_read_like_a_feed() {
        let now = tuesday();
        let hour = 36_000_000_000;
        let day_ticks = TICKS_PER_DAY;
        assert_eq!(when(now - hour, now), "13:05");
        assert_eq!(when(now - day_ticks, now), "yesterday 14:05");
        assert_eq!(when(now - 3 * day_ticks, now), "Sat 14:05");
        assert_eq!(when(now - 10 * day_ticks, now), "10 Oct");
    }
}
