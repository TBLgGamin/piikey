//! The colours of the dashboards: one for each type of personal data, the same in the map, the
//! legend and the tree, and the label colour that reads on any of them.
//!
//! The colours were picked in `OKLab`, where the distance between two colours follows what the eye
//! sees: the types that turn up most often (email, name, address, phone, IBAN, date of birth, card
//! number, place, organization, BSN) got well separated hues, and every other type the colour
//! farthest from all the ones before it. No two of the 44 are closer than 0.08 (a just noticeable
//! difference is 0.02). The same colours serve both themes; a tile's label is white or black,
//! whichever reads better on it.

use piikey::detect::EntityKind;
use windows_reactor::{Border, Color, VerticalAlignment};

/// The colour of the types beyond the ones a view lists, and of a tile that stands for many files.
pub(super) const NEUTRAL: Color = Color::rgb(0x6e, 0x6e, 0x6e);
const WHITE: Color = Color::rgb(0xff, 0xff, 0xff);
const BLACK: Color = Color::rgb(0x00, 0x00, 0x00);

/// The colour of a type of personal data. A `match` without a catch-all, so a type that is added
/// to [`EntityKind`] does not compile until it has a colour.
pub(super) const fn kind_color(kind: EntityKind) -> Color {
    match kind {
        EntityKind::Secret => Color::rgb(0xb1, 0xde, 0x38),
        EntityKind::UrlCredential => Color::rgb(0x85, 0xc0, 0xa9),
        EntityKind::Email => Color::rgb(0x3b, 0x82, 0xd6),
        EntityKind::Iban => Color::rgb(0xd6, 0x43, 0x6a),
        EntityKind::CreditCard => Color::rgb(0x14, 0xa3, 0xb8),
        EntityKind::Ipv6 => Color::rgb(0x43, 0xd0, 0x66),
        EntityKind::Mac => Color::rgb(0xbe, 0x26, 0x0b),
        EntityKind::Ipv4 => Color::rgb(0xed, 0x93, 0xa4),
        EntityKind::UsSsn => Color::rgb(0xd1, 0xc1, 0xf2),
        EntityKind::NlBsn => Color::rgb(0xd9, 0x5f, 0xb8),
        EntityKind::Phone => Color::rgb(0x2f, 0xa8, 0x60),
        EntityKind::Person => Color::rgb(0xef, 0x8a, 0x24),
        EntityKind::PersonAlias => Color::rgb(0x2f, 0x74, 0x7e),
        EntityKind::PersonIdentifier => Color::rgb(0x7f, 0x5a, 0x7d),
        EntityKind::PersonAttribute => Color::rgb(0x95, 0x8d, 0xd8),
        EntityKind::PersonRole => Color::rgb(0x47, 0x58, 0xd4),
        EntityKind::DateOfBirth => Color::rgb(0xc9, 0xa4, 0x00),
        EntityKind::PhoneNumber => Color::rgb(0x3c, 0xea, 0xbf),
        EntityKind::ContactHandle => Color::rgb(0x71, 0xb9, 0xf2),
        EntityKind::PostalAddress => Color::rgb(0x8e, 0x5b, 0xd6),
        EntityKind::Location => Color::rgb(0xa2, 0x68, 0x3d),
        EntityKind::GeoLocation => Color::rgb(0xb5, 0x90, 0x69),
        EntityKind::DeviceId => Color::rgb(0xf7, 0x5e, 0x51),
        EntityKind::IdentifyingLink => Color::rgb(0x68, 0xde, 0xf4),
        EntityKind::AccountId => Color::rgb(0xa7, 0x2d, 0x91),
        EntityKind::AuthSecret => Color::rgb(0x4a, 0x77, 0x33),
        EntityKind::BankAccount => Color::rgb(0xd6, 0x91, 0xf1),
        EntityKind::PaymentCard => Color::rgb(0x87, 0x85, 0x2b),
        EntityKind::CardSecurity => Color::rgb(0xae, 0x64, 0x90),
        EntityKind::FinancialAmount => Color::rgb(0xb9, 0x72, 0xf1),
        EntityKind::DocumentId => Color::rgb(0xdb, 0xca, 0x96),
        EntityKind::DocumentReference => Color::rgb(0xab, 0x3a, 0x5f),
        EntityKind::VehicleId => Color::rgb(0xb9, 0x87, 0xa0),
        EntityKind::OrganizationName => Color::rgb(0x7a, 0x87, 0x94),
        EntityKind::OrganizationId => Color::rgb(0x8d, 0xa5, 0x23),
        EntityKind::ProperName => Color::rgb(0xff, 0xa6, 0xfc),
        EntityKind::HealthData => Color::rgb(0xf5, 0xb9, 0xbb),
        EntityKind::BiometricData => Color::rgb(0x7e, 0xa4, 0x7d),
        EntityKind::EthnicOrigin => Color::rgb(0x42, 0x68, 0xa8),
        EntityKind::PoliticalOpinion => Color::rgb(0x0d, 0x95, 0x7e),
        EntityKind::ReligionOrBelief => Color::rgb(0xfd, 0xbe, 0x45),
        EntityKind::SexualOrientation => Color::rgb(0xd4, 0xa6, 0x86),
        EntityKind::TradeUnion => Color::rgb(0x2f, 0xa0, 0xed),
        EntityKind::CriminalOffence => Color::rgb(0xc5, 0xa3, 0xcd),
    }
}

/// The small square of a type's colour that goes before its name.
pub(super) fn swatch(kind: EntityKind) -> Border {
    Border::new()
        .width(10.0)
        .height(10.0)
        .corner_radius(2.0)
        .background(kind_color(kind))
        .vertical_alignment(VerticalAlignment::Center)
}

/// The brightness of `color` as WCAG defines it, from 0 (black) to 1 (white).
pub(super) fn relative_luminance(color: Color) -> f64 {
    let linear = |value: u8| {
        let c = f64::from(value) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
}

/// The WCAG contrast ratio of two colours, from 1 to 21.
pub(super) fn contrast_ratio(a: Color, b: Color) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The label colour for `color`: pure white or pure black, whichever has the higher contrast. The
/// better of the two is never below 4.58:1.
pub(super) fn text_on(color: Color) -> Color {
    if contrast_ratio(color, WHITE) >= contrast_ratio(color, BLACK) {
        WHITE
    } else {
        BLACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a label needs against its tile: WCAG AA for text.
    const MIN_CONTRAST: f64 = 4.5;

    /// The colour in `OKLab`, where the distance between two colours follows what the eye sees.
    fn oklab(color: Color) -> [f64; 3] {
        let linear = |value: u8| {
            let c = f64::from(value) / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        let (red, green, blue) = (linear(color.r), linear(color.g), linear(color.b));
        let long =
            (0.412_221_470_8 * red + 0.536_332_536_3 * green + 0.051_445_992_9 * blue).cbrt();
        let medium =
            (0.211_903_498_2 * red + 0.680_699_545_1 * green + 0.107_396_956_6 * blue).cbrt();
        let short =
            (0.088_302_461_9 * red + 0.281_718_837_6 * green + 0.629_978_700_5 * blue).cbrt();
        [
            0.210_454_255_3 * long + 0.793_617_785_0 * medium - 0.004_072_046_8 * short,
            1.977_998_495_1 * long - 2.428_592_205_0 * medium + 0.450_593_709_9 * short,
            0.025_904_037_1 * long + 0.782_771_766_2 * medium - 0.808_675_766_0 * short,
        ]
    }

    fn distance(a: Color, b: Color) -> f64 {
        let (a, b) = (oklab(a), oklab(b));
        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
    }

    #[test]
    fn every_type_has_a_colour_of_its_own_that_the_eye_tells_apart() {
        for (i, a) in EntityKind::ALL.iter().enumerate() {
            for b in &EntityKind::ALL[i + 1..] {
                let apart = distance(kind_color(*a), kind_color(*b));
                assert!(
                    apart >= 0.08,
                    "{} and {} are only {apart:.3} apart",
                    a.label(),
                    b.label()
                );
            }
        }
    }

    #[test]
    fn no_type_looks_like_the_neutral_grey() {
        for kind in EntityKind::ALL {
            let apart = distance(kind_color(kind), NEUTRAL);
            assert!(apart >= 0.05, "{} is {apart:.3} from grey", kind.label());
        }
    }

    #[test]
    fn a_label_reads_on_every_colour() {
        for kind in EntityKind::ALL {
            let color = kind_color(kind);
            let ratio = contrast_ratio(color, text_on(color));
            assert!(ratio >= MIN_CONTRAST, "{}: {ratio:.2}", kind.label());
        }
        let ratio = contrast_ratio(NEUTRAL, text_on(NEUTRAL));
        assert!(ratio >= MIN_CONTRAST, "neutral: {ratio:.2}");
    }

    #[test]
    fn the_label_is_pure_white_or_black_whichever_reads_better() {
        assert_eq!(text_on(Color::rgb(0x20, 0x20, 0x20)), WHITE);
        assert_eq!(text_on(Color::rgb(0xf0, 0xf0, 0xf0)), BLACK);
        assert_eq!(text_on(WHITE), BLACK);
        assert_eq!(text_on(BLACK), WHITE);
    }
}
