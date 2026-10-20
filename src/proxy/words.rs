//! Word lists for believable proxies. All entries are lowercase ASCII letters
//! (or, for [`FREEMAIL`], plain domains) so they drop straight into email local
//! parts and domain labels without escaping.

/// Common US and Dutch given names.
pub(super) const FIRST: [&str; 200] = [
    "james",
    "john",
    "robert",
    "michael",
    "william",
    "david",
    "richard",
    "joseph",
    "thomas",
    "charles",
    "daniel",
    "matthew",
    "anthony",
    "mark",
    "donald",
    "steven",
    "paul",
    "andrew",
    "joshua",
    "kenneth",
    "kevin",
    "brian",
    "george",
    "edward",
    "ronald",
    "timothy",
    "jason",
    "jeffrey",
    "ryan",
    "jacob",
    "gary",
    "nicholas",
    "eric",
    "jonathan",
    "stephen",
    "larry",
    "justin",
    "scott",
    "brandon",
    "benjamin",
    "samuel",
    "gregory",
    "frank",
    "patrick",
    "raymond",
    "jack",
    "dennis",
    "jerry",
    "tyler",
    "aaron",
    "adam",
    "nathan",
    "henry",
    "douglas",
    "zachary",
    "mary",
    "patricia",
    "jennifer",
    "linda",
    "elizabeth",
    "barbara",
    "susan",
    "jessica",
    "sarah",
    "karen",
    "lisa",
    "nancy",
    "betty",
    "margaret",
    "sandra",
    "ashley",
    "kimberly",
    "emily",
    "donna",
    "michelle",
    "carol",
    "amanda",
    "dorothy",
    "melissa",
    "deborah",
    "stephanie",
    "rebecca",
    "sharon",
    "laura",
    "cynthia",
    "kathleen",
    "amy",
    "angela",
    "shirley",
    "anna",
    "brenda",
    "pamela",
    "emma",
    "nicole",
    "helen",
    "samantha",
    "katherine",
    "christine",
    "debra",
    "rachel",
    "carolyn",
    "janet",
    "catherine",
    "maria",
    "heather",
    "diane",
    "ruth",
    "julie",
    "olivia",
    "joyce",
    "jan",
    "piet",
    "kees",
    "henk",
    "willem",
    "johannes",
    "cornelis",
    "hendrik",
    "gerrit",
    "dirk",
    "pieter",
    "marcel",
    "rob",
    "bas",
    "sander",
    "joost",
    "ruud",
    "wouter",
    "thijs",
    "daan",
    "sven",
    "lars",
    "tim",
    "jeroen",
    "maarten",
    "bart",
    "niels",
    "stefan",
    "rick",
    "erik",
    "martijn",
    "tom",
    "jasper",
    "floris",
    "koen",
    "stijn",
    "bram",
    "sjoerd",
    "wim",
    "hans",
    "frans",
    "arjen",
    "gert",
    "harm",
    "jelle",
    "sanne",
    "anne",
    "lotte",
    "fleur",
    "femke",
    "eline",
    "iris",
    "sophie",
    "lieke",
    "marloes",
    "anouk",
    "nienke",
    "esther",
    "marieke",
    "ingrid",
    "petra",
    "hanneke",
    "wilma",
    "trudy",
    "jolanda",
    "saskia",
    "mirjam",
    "yvonne",
    "karin",
    "ellen",
    "marijke",
    "monique",
    "inge",
    "loes",
    "mila",
    "tess",
    "noor",
    "roos",
    "evi",
    "lynn",
    "maud",
    "floor",
    "dewi",
    "annelies",
    "margriet",
    "geertje",
    "johanna",
    "cornelia",
    "maaike",
    "marja",
];

/// Common US and Dutch surnames; Dutch particles are fused (`vandenberg`).
pub(super) const LAST: [&str; 200] = [
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "garcia",
    "miller",
    "davis",
    "rodriguez",
    "martinez",
    "hernandez",
    "lopez",
    "gonzalez",
    "wilson",
    "anderson",
    "thomas",
    "taylor",
    "moore",
    "jackson",
    "martin",
    "lee",
    "perez",
    "thompson",
    "white",
    "harris",
    "sanchez",
    "clark",
    "ramirez",
    "lewis",
    "robinson",
    "walker",
    "young",
    "allen",
    "king",
    "wright",
    "scott",
    "torres",
    "nguyen",
    "hill",
    "flores",
    "green",
    "adams",
    "nelson",
    "baker",
    "hall",
    "rivera",
    "campbell",
    "mitchell",
    "carter",
    "roberts",
    "gomez",
    "phillips",
    "evans",
    "turner",
    "diaz",
    "parker",
    "cruz",
    "edwards",
    "collins",
    "reyes",
    "stewart",
    "morris",
    "morales",
    "murphy",
    "cook",
    "rogers",
    "gutierrez",
    "ortiz",
    "morgan",
    "cooper",
    "peterson",
    "bailey",
    "reed",
    "kelly",
    "howard",
    "ramos",
    "kim",
    "cox",
    "ward",
    "richardson",
    "watson",
    "brooks",
    "chavez",
    "wood",
    "james",
    "bennett",
    "gray",
    "mendoza",
    "ruiz",
    "hughes",
    "price",
    "alvarez",
    "castillo",
    "sanders",
    "patel",
    "myers",
    "long",
    "ross",
    "foster",
    "jimenez",
    "jansen",
    "devries",
    "vandijk",
    "bakker",
    "janssen",
    "visser",
    "smit",
    "meijer",
    "deboer",
    "mulder",
    "degroot",
    "bos",
    "vos",
    "peters",
    "hendriks",
    "dekker",
    "brouwer",
    "dewit",
    "dijkstra",
    "smits",
    "degraaf",
    "kok",
    "jacobs",
    "dehaan",
    "vermeulen",
    "debruijn",
    "debruin",
    "schouten",
    "willems",
    "hoekstra",
    "maas",
    "verhoeven",
    "koster",
    "prins",
    "blom",
    "huisman",
    "peeters",
    "kuipers",
    "vandam",
    "kramer",
    "bosman",
    "mol",
    "scholten",
    "deruiter",
    "post",
    "kuiper",
    "hermans",
    "hofman",
    "jonker",
    "wolters",
    "vandenberg",
    "vanleeuwen",
    "vanderveen",
    "vanbeek",
    "vanvliet",
    "vandeven",
    "vanwijk",
    "vanderwal",
    "bouwman",
    "koning",
    "timmer",
    "groen",
    "driessen",
    "mertens",
    "wouters",
    "maes",
    "claes",
    "aarts",
    "brands",
    "brink",
    "smeets",
    "hoogland",
    "lammers",
    "molenaar",
    "wolff",
    "zwart",
    "bakkers",
    "slot",
    "bosch",
    "vink",
    "verbeek",
    "hartog",
    "kroon",
    "otten",
    "leenders",
    "haas",
    "schipper",
    "kuijpers",
    "franssen",
    "gerritsen",
    "hamers",
    "dejong",
    "veldman",
    "kooistra",
    "bruggeman",
    "zijlstra",
    "postma",
    "mulders",
    "dekkers",
    "bergman",
];

/// Short neutral nouns; two of them make a believable company domain label.
pub(super) const WORDS: [&str; 128] = [
    "anchor", "arrow", "aspen", "atlas", "badge", "basil", "beacon", "birch", "bison", "bloom",
    "bridge", "brook", "canyon", "cedar", "chalk", "cliff", "cloud", "clover", "comet", "coral",
    "crane", "creek", "crest", "crown", "dawn", "delta", "dune", "eagle", "echo", "ember", "fern",
    "field", "finch", "flint", "forge", "frost", "garden", "glade", "glen", "grove", "harbor",
    "hawk", "hazel", "heron", "holly", "iris", "island", "ivory", "jade", "jasper", "juniper",
    "kelp", "lagoon", "lake", "lantern", "larch", "lark", "laurel", "ledge", "lily", "linden",
    "lotus", "lunar", "maple", "marble", "marsh", "meadow", "mesa", "mill", "mist", "moss",
    "north", "oak", "oasis", "olive", "onyx", "orbit", "orchard", "otter", "pearl", "pebble",
    "pine", "plume", "pond", "prairie", "quartz", "quill", "rain", "rapids", "raven", "reef",
    "ridge", "river", "robin", "rowan", "sable", "sage", "sand", "shore", "silver", "slate",
    "sparrow", "spring", "spruce", "star", "stone", "storm", "stream", "summit", "sun", "swan",
    "thistle", "thorn", "tide", "timber", "trail", "tulip", "tundra", "valley", "velvet", "violet",
    "walnut", "wave", "willow", "winter", "wren", "zenith", "zephyr",
];

/// First half of an invented place name (`ash` + `ford`); lowercase, never a given name,
/// surname or stopword.
pub(super) const PLACE_HEAD: [&str; 64] = [
    "ash", "mill", "west", "oak", "stone", "brook", "east", "south", "elm", "birch", "pine", "fox",
    "wolf", "bear", "deer", "raven", "swan", "hart", "alder", "queen", "aspen", "fern", "high",
    "low", "frost", "glade", "red", "heron", "black", "grey", "clay", "sand", "rock", "cliff",
    "marsh", "fen", "moor", "heath", "larch", "holt", "hazel", "thorn", "rose", "lily", "iron",
    "gold", "silver", "copper", "salt", "lake", "river", "spring", "linden", "bridge", "church",
    "abbey", "castle", "tower", "bay", "cove", "glen", "ridge", "maple", "dun",
];

/// Second half of an invented place name.
pub(super) const PLACE_TAIL: [&str; 64] = [
    "ford", "field", "haven", "wick", "dale", "mere", "ton", "ham", "ley", "worth", "bury",
    "stead", "stoke", "thorpe", "combe", "hurst", "den", "mouth", "port", "bridge", "cross",
    "gate", "side", "holt", "land", "rise", "ridge", "vale", "glen", "moor", "fell", "heath",
    "marsh", "holm", "stow", "spring", "wall", "barrow", "cliff", "bank", "shaw", "weald",
    "hollow", "strand", "water", "lake", "pool", "beck", "burn", "firth", "ness", "wyke", "garth",
    "fold", "croft", "bourne", "park", "point", "view", "rest", "end", "mount", "rock", "stone",
];

/// First half of an invented organization or brand word (`north` + `stone`).
pub(super) const ORG_HEAD: [&str; 64] = [
    "north", "bright", "silver", "blue", "iron", "clear", "swift", "prime", "nova", "apex",
    "vertex", "summit", "cedar", "pure", "true", "open", "fresh", "solid", "rapid", "smart",
    "keen", "bold", "grand", "royal", "first", "alpha", "delta", "omega", "sigma", "zenith",
    "polar", "solar", "lunar", "stellar", "cobalt", "amber", "crimson", "scarlet", "azure",
    "ivory", "onyx", "jade", "coral", "topaz", "opal", "pearl", "quartz", "granite", "urban",
    "metro", "civic", "global", "union", "pacific", "atlantic", "nordic", "eastern", "western",
    "golden", "crystal", "sterling", "harbor", "beacon", "anchor",
];

/// Second half of an invented organization or brand word.
pub(super) const ORG_TAIL: [&str; 64] = [
    "stone", "wave", "bridge", "point", "forge", "light", "yard", "field", "gate", "peak", "ridge",
    "crest", "bay", "port", "vale", "cliff", "tree", "leaf", "root", "seed", "bloom", "grove",
    "timber", "fire", "spark", "flame", "glow", "beam", "ray", "star", "moon", "sun", "path",
    "span", "road", "trail", "track", "line", "link", "bond", "net", "web", "grid", "node", "hub",
    "core", "base", "sign", "wing", "hawk", "fox", "lynx", "wolf", "bear", "lion", "eagle",
    "shield", "guard", "tower", "cove", "arch", "dome", "vault", "haven",
];

/// Words that close an invented organization name when the original had several words.
pub(super) const ORG_FORM: [&str; 8] = [
    "group", "partners", "labs", "works", "company", "studio", "holding", "systems",
];

/// Legal forms, lowercase and without a trailing dot. An organization keeps its own.
pub(super) const LEGAL_FORMS: [&str; 18] = [
    "bv", "b.v", "nv", "n.v", "gmbh", "ag", "ltd", "llc", "inc", "plc", "sa", "sarl", "srl", "spa",
    "oy", "ab", "as", "kg",
];

/// Street-name endings in the languages the model covers.
pub(super) const STREET_TAIL: [&str; 16] = [
    "straat", "laan", "weg", "plein", "gracht", "kade", "road", "street", "lane", "avenue", "way",
    "strasse", "gasse", "rue", "via", "ulica",
];

/// Public mailbox providers: their domain carries no information about the person,
/// so an email on one of them keeps its domain.
pub(super) const FREEMAIL: [&str; 23] = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.de",
    "gmx.net",
    "web.de",
    "t-online.de",
    "ziggo.nl",
    "kpnmail.nl",
    "hetnet.nl",
    "xs4all.nl",
    "planet.nl",
    "home.nl",
    "telenet.be",
    "skynet.be",
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        FIRST, FREEMAIL, LAST, LEGAL_FORMS, ORG_FORM, ORG_HEAD, ORG_TAIL, PLACE_HEAD, PLACE_TAIL,
        STREET_TAIL, WORDS,
    };
    use crate::restore::STOPWORDS;

    fn assert_clean(name: &str, list: &[&str]) {
        let unique: HashSet<&str> = list.iter().copied().collect();
        assert_eq!(unique.len(), list.len(), "{name} has duplicates");
        for word in list {
            assert!((2..=10).contains(&word.len()), "{name}: {word}");
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase()),
                "{name}: {word}"
            );
        }
    }

    #[test]
    fn name_and_word_lists_are_unique_lowercase_ascii() {
        assert_clean("FIRST", &FIRST);
        assert_clean("LAST", &LAST);
        assert_clean("WORDS", &WORDS);
        for (name, list) in [
            ("PLACE_HEAD", &PLACE_HEAD[..]),
            ("PLACE_TAIL", &PLACE_TAIL[..]),
            ("ORG_HEAD", &ORG_HEAD[..]),
            ("ORG_TAIL", &ORG_TAIL[..]),
            ("ORG_FORM", &ORG_FORM[..]),
            ("STREET_TAIL", &STREET_TAIL[..]),
        ] {
            assert_clean(name, list);
        }
    }

    #[test]
    fn legal_forms_are_unique_lowercase_without_trailing_dot() {
        let unique: HashSet<&str> = LEGAL_FORMS.iter().copied().collect();
        assert_eq!(unique.len(), LEGAL_FORMS.len());
        for form in LEGAL_FORMS {
            assert!(
                form.bytes().all(|b| b.is_ascii_lowercase() || b == b'.') && !form.ends_with('.'),
                "{form}"
            );
        }
    }

    #[test]
    fn names_are_not_everyday_words() {
        // The restorer puts the original's part back wherever a name part of a proxy shows up
        // by itself. A name that is also a word (`will`, `may`, `de`) would hit ordinary text.
        for (name, list) in [
            ("FIRST", &FIRST[..]),
            ("LAST", &LAST[..]),
            ("PLACE_HEAD", &PLACE_HEAD[..]),
            ("PLACE_TAIL", &PLACE_TAIL[..]),
            ("ORG_HEAD", &ORG_HEAD[..]),
            ("ORG_TAIL", &ORG_TAIL[..]),
        ] {
            for word in list {
                assert!(!STOPWORDS.contains(word), "{name}: {word} is a stopword");
            }
        }
        for (name, list) in [
            ("PLACE_HEAD", &PLACE_HEAD[..]),
            ("PLACE_TAIL", &PLACE_TAIL[..]),
            ("ORG_HEAD", &ORG_HEAD[..]),
            ("ORG_TAIL", &ORG_TAIL[..]),
        ] {
            for word in list {
                assert!(!FIRST.contains(word), "{name}: {word} is a given name");
                assert!(!LAST.contains(word), "{name}: {word} is a surname");
            }
        }
    }

    #[test]
    fn mailbox_providers_are_unique_lowercase_domains() {
        let unique: HashSet<&str> = FREEMAIL.iter().copied().collect();
        assert_eq!(unique.len(), FREEMAIL.len());
        for domain in FREEMAIL {
            let (label, tld) = domain.rsplit_once('.').unwrap_or_default();
            assert!(
                !label.is_empty() && (2..=24).contains(&tld.len()),
                "{domain}"
            );
            assert_eq!(domain, domain.to_ascii_lowercase(), "{domain}");
            assert!(
                domain.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'-')),
                "{domain}"
            );
        }
    }
}
