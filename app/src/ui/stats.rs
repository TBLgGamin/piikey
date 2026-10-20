//! Values masked and restored per local day, for the Home page chart. Kept for [`KEPT`] days in
//! `%LOCALAPPDATA%\piikey\stats.cfg`, one line per day: `<day> <masked> <restored>`, where `<day>`
//! counts local days since 1601-01-01 (Windows file time divided by a day).

use std::{collections::BTreeMap, fmt::Write};

use windows_reactor::DateTime;

/// Days kept on disk; older ones are dropped when saved.
const KEPT: i64 = 90;
/// Windows file time ticks (100 ns) in a day.
const TICKS_PER_DAY: i64 = 864_000_000_000;

/// A local day: days since 1601-01-01.
pub type DayIndex = i64;

/// Today, local time.
pub fn today() -> DayIndex {
    DateTime::now().to_local().ticks().div_euclid(TICKS_PER_DAY)
}

/// The day of the month, for a chart axis.
pub fn day_of_month(day: DayIndex) -> u32 {
    DateTime::from_ticks(day * TICKS_PER_DAY).day()
}

/// One day of the chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Day {
    pub index: DayIndex,
    pub masked: u64,
    pub restored: u64,
}

/// The counts of every day kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    days: BTreeMap<DayIndex, (u64, u64)>,
}

impl Stats {
    /// Reads the file text; lines that do not parse are skipped.
    pub fn parse(text: &str) -> Self {
        let days = text
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_ascii_whitespace().map(str::parse::<i64>);
                let (Some(Ok(day)), Some(Ok(masked)), Some(Ok(restored)), None) =
                    (fields.next(), fields.next(), fields.next(), fields.next())
                else {
                    return None;
                };
                Some((day, (masked.try_into().ok()?, restored.try_into().ok()?)))
            })
            .collect();
        Self { days }
    }

    /// The file text, without days older than [`KEPT`] before `today`.
    pub fn to_text(&self, today: DayIndex) -> String {
        self.days.range(today - KEPT + 1..).fold(
            String::new(),
            |mut text, (day, (masked, restored))| {
                // Writing to a String cannot fail.
                let _ = writeln!(text, "{day} {masked} {restored}");
                text
            },
        )
    }

    pub fn add(&mut self, day: DayIndex, masked: u64, restored: u64) {
        let counts = self.days.entry(day).or_default();
        counts.0 += masked;
        counts.1 += restored;
    }

    /// The `n` days that end with `today`, oldest first; days without traffic count zero.
    pub fn last(&self, today: DayIndex, n: i64) -> Vec<Day> {
        (today - n + 1..=today)
            .map(|day| {
                let (masked, restored) = self.days.get(&day).copied().unwrap_or_default();
                Day {
                    index: day,
                    masked,
                    restored,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_add_up_per_day_and_round_trip_through_the_file() {
        let mut stats = Stats::default();
        stats.add(1000, 2, 0);
        stats.add(1000, 3, 4);
        stats.add(1002, 1, 1);
        let again = Stats::parse(&stats.to_text(1002));
        assert_eq!(again, stats);
        assert_eq!(
            again.last(1002, 3),
            [
                Day {
                    index: 1000,
                    masked: 5,
                    restored: 4
                },
                Day {
                    index: 1001,
                    masked: 0,
                    restored: 0
                },
                Day {
                    index: 1002,
                    masked: 1,
                    restored: 1
                },
            ]
        );
    }

    #[test]
    fn old_days_are_dropped_on_save_and_bad_lines_skipped() {
        let stats = Stats::parse("10 1 1\n500 2 2\nnot a day\n501 -1 2\n502 1 2 3\n");
        assert_eq!(stats.to_text(500 + KEPT - 1), "500 2 2\n");
        assert_eq!(stats.to_text(500 + KEPT), "");
    }

    #[test]
    fn days_map_back_to_their_date() {
        // 2026-10-20, midnight.
        let day = DateTime::from_unix_secs(1_792_454_400).ticks() / TICKS_PER_DAY;
        assert_eq!(day_of_month(day), 20);
        assert_eq!(day_of_month(day + 12), 1, "November 1st");
    }
}
