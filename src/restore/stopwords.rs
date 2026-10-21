//! Words too common to stand for a name by themselves.
//!
//! Tolerant restore replaces a bare name part (`Haley` for `Haley van Zessen`). A part that
//! is also an everyday word (`may`, `will`, `van`) would turn ordinary prose into the user's
//! real name, so those parts are never restored on their own.

/// The ~350 most common English and Dutch words, mostly function words.
///
/// Lowercase ASCII, sorted and unique, so a lookup is a binary search. The proxy name lists
/// must not contain any of them.
pub(crate) const STOPWORDS: &[&str] = &[
    "a", "aan", "about", "above", "across", "after", "again", "against", "all", "alle", "alleen",
    "almost", "alone", "along", "already", "als", "also", "although", "altijd", "always", "am",
    "among", "an", "and", "andere", "another", "any", "anyone", "anyway", "are", "around", "as",
    "at", "away", "back", "be", "became", "because", "become", "been", "before", "behind", "being",
    "below", "ben", "bent", "beside", "between", "beyond", "bij", "both", "but", "by", "came",
    "can", "cannot", "come", "could", "daar", "dan", "dat", "de", "deze", "did", "die", "dit",
    "do", "doen", "does", "doing", "done", "door", "down", "during", "dus", "each", "een", "eens",
    "either", "else", "en", "enough", "er", "erg", "even", "ever", "every", "few", "for", "from",
    "further", "geen", "get", "gets", "geweest", "give", "given", "gives", "go", "goes", "going",
    "gone", "got", "graag", "haar", "had", "hadden", "has", "have", "having", "he", "heb",
    "hebben", "hebt", "heeft", "heel", "hem", "her", "here", "hers", "herself", "het", "hier",
    "hij", "him", "himself", "his", "hoe", "how", "however", "hun", "iemand", "iets", "if", "ik",
    "in", "into", "is", "it", "its", "itself", "ja", "je", "jij", "jou", "jouw", "jullie", "just",
    "kan", "keep", "kept", "know", "known", "kon", "konden", "kunnen", "kunt", "less", "let",
    "maar", "made", "mag", "make", "many", "may", "maybe", "me", "meer", "men", "met", "might",
    "mij", "mijn", "mine", "moet", "moeten", "mogen", "more", "most", "much", "must", "my",
    "myself", "na", "naar", "near", "need", "never", "new", "next", "niet", "niets", "no",
    "nobody", "nog", "none", "nooit", "nor", "not", "nothing", "now", "nu", "of", "off", "often",
    "old", "om", "omdat", "on", "once", "onder", "one", "only", "ons", "onto", "onze", "ook", "op",
    "or", "other", "others", "our", "ours", "out", "over", "own", "per", "put", "quite", "rather",
    "really", "reeds", "said", "same", "say", "says", "see", "seem", "seen", "she", "should",
    "since", "sinds", "so", "some", "soms", "soon", "still", "such", "take", "te", "tegen", "than",
    "that", "the", "their", "theirs", "them", "then", "there", "these", "they", "thing", "think",
    "this", "those", "though", "through", "thus", "till", "to", "toch", "toen", "too", "took",
    "tot", "toward", "tussen", "two", "u", "uit", "under", "unless", "until", "up", "upon", "us",
    "use", "used", "using", "uw", "vaak", "van", "veel", "very", "voor", "waar", "waarom",
    "wanneer", "want", "waren", "was", "wat", "way", "we", "weinig", "wel", "welk", "welke",
    "well", "went", "werd", "were", "what", "when", "where", "whether", "which", "while", "who",
    "whom", "whose", "why", "wie", "wij", "wil", "will", "willen", "with", "within", "without",
    "worden", "wordt", "would", "yes", "yet", "you", "your", "yours", "yourself", "zal", "ze",
    "zeer", "zelf", "zich", "zij", "zijn", "zo", "zonder", "zou", "zouden", "zullen",
];
