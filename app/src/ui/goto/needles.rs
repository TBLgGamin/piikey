//! What to look for in a text when the value is all that is known: the value as it is, then the
//! parts of it that are likelier to be in the text just as they are.
//!
//! The findings list shows a value with every run of white space made one space, and a value of
//! more than 4,096 characters cut off and ended with `…`. A text can hold the value with a line
//! break where the list shows a space, so the whole value is not always there to be found.

/// The character that ends a value that was cut short.
const ELLIPSIS: char = '…';
/// The fewest characters a part of a value needs to be looked for on its own: a shorter one is in
/// far too many places to say anything.
const MIN_PIECE: usize = 4;

/// One thing to look for: `text`, and whether the letter case may differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Needle {
    pub(super) text: String,
    pub(super) ignore_case: bool,
}

/// What to look for, the most exact first: the value; the value without the `…` that says it was
/// cut; and, for a value of several words, its longest word of at least four characters. Each one
/// as it is, then in any letter case when it has letters. Nothing for a value without characters.
pub(super) fn needles(value: &str) -> Vec<Needle> {
    let value = value.trim();
    let cut = value.strip_suffix(ELLIPSIS).map(str::trim_end);
    let mut texts: Vec<&str> = Vec::new();
    for text in [Some(value), cut, longest_piece(cut.unwrap_or(value))]
        .into_iter()
        .flatten()
    {
        if !text.is_empty() && !texts.contains(&text) {
            texts.push(text);
        }
    }
    texts
        .into_iter()
        .flat_map(|text| {
            let exact = Needle {
                text: text.to_owned(),
                ignore_case: false,
            };
            let any = has_case(text).then(|| Needle {
                text: text.to_owned(),
                ignore_case: true,
            });
            [Some(exact), any].into_iter().flatten()
        })
        .collect()
}

/// The longest word of `text` that has at least [`MIN_PIECE`] characters, the first of equals; none
/// for a text of one word, which is its own longest word.
fn longest_piece(text: &str) -> Option<&str> {
    text.split_whitespace().nth(1)?;
    let mut best: Option<(&str, usize)> = None;
    for piece in text.split_whitespace() {
        let length = piece.chars().count();
        if length >= MIN_PIECE && best.is_none_or(|(_, longest)| length > longest) {
            best = Some((piece, length));
        }
    }
    best.map(|(piece, _)| piece)
}

/// Whether the letter case of `text` can make a difference.
fn has_case(text: &str) -> bool {
    text.chars().any(|c| c.is_lowercase() || c.is_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `needles` gives for `value`, as (text, ignore case) pairs.
    fn looked_for(value: &str) -> Vec<(String, bool)> {
        needles(value)
            .into_iter()
            .map(|needle| (needle.text, needle.ignore_case))
            .collect()
    }

    /// The two ways to look for `text` that has letters: as it is, then in any case.
    fn both(text: &str) -> [(String, bool); 2] {
        [(text.to_owned(), false), (text.to_owned(), true)]
    }

    #[test]
    fn the_value_comes_first_as_it_is_and_then_in_any_letter_case() {
        assert_eq!(looked_for("jan@example.com"), both("jan@example.com"));
    }

    #[test]
    fn a_value_without_letters_is_looked_for_in_one_case_only() {
        assert_eq!(looked_for("0612345678"), [("0612345678".to_owned(), false)]);
    }

    #[test]
    fn a_value_of_several_words_falls_back_to_its_longest_word() {
        let mut expected = both("Jan de Vries Amsterdam").to_vec();
        expected.extend(both("Amsterdam"));
        assert_eq!(looked_for("Jan de Vries Amsterdam"), expected);
    }

    #[test]
    fn of_two_longest_words_the_first_is_taken() {
        let mut expected = both("Hello World").to_vec();
        expected.extend(both("Hello"));
        assert_eq!(looked_for("Hello World"), expected);
    }

    #[test]
    fn words_of_fewer_than_four_characters_are_not_looked_for_alone() {
        assert_eq!(looked_for("Jan de Wit"), both("Jan de Wit"));
        // Four characters are enough: digits count, and without letters one case is enough.
        assert_eq!(
            looked_for("+31 6 1234 5678"),
            [
                ("+31 6 1234 5678".to_owned(), false),
                ("1234".to_owned(), false)
            ]
        );
    }

    #[test]
    fn a_value_that_was_cut_is_also_looked_for_without_its_ellipsis() {
        let mut expected = both("Keizersgracht 123…").to_vec();
        expected.extend(both("Keizersgracht 123"));
        expected.extend(both("Keizersgracht"));
        assert_eq!(looked_for("Keizersgracht 123…"), expected);

        // A space before the ellipsis goes with it, and the word comes from what is left.
        let mut expected = both("Hello World …").to_vec();
        expected.extend(both("Hello World"));
        expected.extend(both("Hello"));
        assert_eq!(looked_for("Hello World …"), expected);
    }

    #[test]
    fn a_long_value_is_looked_for_whole() {
        let value = format!("{}…", "x".repeat(4096));
        let found = needles(&value);
        let lengths: Vec<usize> = found.iter().map(|n| n.text.chars().count()).collect();
        assert_eq!(lengths, [4097, 4097, 4096, 4096]);
        assert_eq!(found.first().map(|n| n.ignore_case), Some(false));
    }

    #[test]
    fn an_empty_value_is_looked_for_nowhere() {
        assert!(needles("").is_empty());
        assert!(needles("  \t ").is_empty());
    }
}
