//! Words about the types of personal data a file or a folder holds: the lists that go in a tooltip,
//! under a name in the tree, and in the details.

use piikey::detect::EntityKind;

/// What `kind` makes of `counts`: all of them, or only the ones of that type.
fn only(counts: &[(EntityKind, u32)], kind: Option<EntityKind>) -> Vec<(EntityKind, u32)> {
    counts
        .iter()
        .copied()
        .filter(|&(of, _)| kind.is_none_or(|kind| kind == of))
        .collect()
}

/// `Email 8, Name 3, +2 more`: the `max` types that hold most, with how many of each. With a
/// `kind` the one type, whatever `max` is.
pub(super) fn summary(
    counts: &[(EntityKind, u32)],
    kind: Option<EntityKind>,
    max: usize,
) -> String {
    let counts = only(counts, kind);
    let mut parts: Vec<String> = counts
        .iter()
        .take(max)
        .map(|&(kind, n)| format!("{} {n}", kind.label()))
        .collect();
    if counts.len() > max {
        parts.push(format!("+{} more", counts.len() - max));
    }
    parts.join(", ")
}

/// `Email, Name +2`: the names of the `max` types that hold most, and how many more there are.
pub(super) fn names(counts: &[(EntityKind, u32)], max: usize) -> String {
    let text = counts
        .iter()
        .take(max)
        .map(|&(kind, _)| kind.label())
        .collect::<Vec<_>>()
        .join(", ");
    if counts.len() > max {
        format!("{text} +{}", counts.len() - max)
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTS: [(EntityKind, u32); 4] = [
        (EntityKind::Email, 8),
        (EntityKind::Person, 3),
        (EntityKind::Phone, 2),
        (EntityKind::Iban, 1),
    ];

    #[test]
    fn a_summary_names_the_types_that_hold_most_and_counts_the_rest() {
        assert_eq!(summary(&COUNTS, None, 2), "Email 8, Name 3, +2 more");
        assert_eq!(
            summary(&COUNTS, None, 4),
            "Email 8, Name 3, Phone 2, IBAN 1"
        );
        assert_eq!(summary(&[], None, 3), "");
    }

    #[test]
    fn a_summary_of_one_type_is_that_type() {
        assert_eq!(summary(&COUNTS, Some(EntityKind::Phone), 1), "Phone 2");
        assert_eq!(summary(&COUNTS, Some(EntityKind::Mac), 1), "");
    }

    #[test]
    fn names_say_which_types_without_the_numbers() {
        assert_eq!(names(&COUNTS, 2), "Email, Name +2");
        assert_eq!(names(&COUNTS, 4), "Email, Name, Phone, IBAN");
        assert_eq!(names(&[], 2), "");
    }
}
