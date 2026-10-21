//! The model's label set and how each entity type maps to a piikey [`EntityKind`].
//!
//! The model has 35 entity types in BIO tagging: logit `0` is `O` (no entity), logit `i >= 1`
//! belongs to type `(i - 1) / 2` and is its `B-` tag when `i` is odd, its `I-` tag when even. The
//! types are listed in the order of the model's `config.json`, which is alphabetical.

use crate::detect::{EntityKind, KindSet, validate::accepts};

/// The entity types, by type index: the name in the model's `config.json`, the kind the type's
/// values usually have, and the kind to use when they fail that kind's validator.
pub(super) const TYPES: [(&str, EntityKind, Option<EntityKind>); 35] = [
    ("ACCOUNT_IDENTIFIER", EntityKind::AccountId, None),
    (
        "AUTH_SECRET",
        EntityKind::Secret,
        Some(EntityKind::AuthSecret),
    ),
    (
        "BANK_ACCOUNT_IDENTIFIER",
        EntityKind::Iban,
        Some(EntityKind::BankAccount),
    ),
    ("BIOMETRIC_DATA", EntityKind::BiometricData, None),
    ("CONTACT_HANDLE", EntityKind::ContactHandle, None),
    ("CRIMINAL_OFFENCE_DATA", EntityKind::CriminalOffence, None),
    ("DATE_OF_BIRTH", EntityKind::DateOfBirth, None),
    ("DEVICE_IDENTIFIER", EntityKind::DeviceId, None),
    ("DOCUMENT_IDENTIFIER", EntityKind::DocumentId, None),
    ("DOCUMENT_REFERENCE", EntityKind::DocumentReference, None),
    ("EMAIL_ADDRESS", EntityKind::Email, None),
    ("ETHNIC_ORIGIN", EntityKind::EthnicOrigin, None),
    ("FINANCIAL_AMOUNT", EntityKind::FinancialAmount, None),
    ("GEO_LOCATION", EntityKind::GeoLocation, None),
    ("HEALTH_DATA", EntityKind::HealthData, None),
    ("IDENTIFYING_LINK", EntityKind::IdentifyingLink, None),
    ("IP_ADDRESS", EntityKind::Ipv4, Some(EntityKind::Ipv6)),
    ("LOCATION", EntityKind::Location, None),
    ("ORGANIZATION_IDENTIFIER", EntityKind::OrganizationId, None),
    ("ORGANIZATION_NAME", EntityKind::OrganizationName, None),
    (
        "PAYMENT_CARD",
        EntityKind::CreditCard,
        Some(EntityKind::PaymentCard),
    ),
    ("PAYMENT_CARD_SECURITY", EntityKind::CardSecurity, None),
    ("PERSON_ALIAS", EntityKind::PersonAlias, None),
    ("PERSON_ATTRIBUTE", EntityKind::PersonAttribute, None),
    ("PERSON_IDENTIFIER", EntityKind::PersonIdentifier, None),
    ("PERSON_NAME", EntityKind::Person, None),
    ("PERSON_ROLE_OR_TITLE", EntityKind::PersonRole, None),
    (
        "PHONE_NUMBER",
        EntityKind::Phone,
        Some(EntityKind::PhoneNumber),
    ),
    ("POLITICAL_OPINION", EntityKind::PoliticalOpinion, None),
    ("POSTAL_ADDRESS", EntityKind::PostalAddress, None),
    ("PROPER_NAME", EntityKind::ProperName, None),
    ("RELIGION_OR_BELIEF", EntityKind::ReligionOrBelief, None),
    ("SEXUAL_ORIENTATION", EntityKind::SexualOrientation, None),
    ("TRADE_UNION_MEMBERSHIP", EntityKind::TradeUnion, None),
    ("VEHICLE_IDENTIFIER", EntityKind::VehicleId, None),
];

/// Logits per token: `O` plus a `B-` and an `I-` tag for each type.
pub(super) const LABELS: usize = 1 + 2 * TYPES.len();

/// Columns of a per-type distribution: one per type, then `O` last.
pub(super) const COLUMNS: usize = TYPES.len() + 1;

/// Column of `O` in a per-type distribution.
pub(super) const O: usize = TYPES.len();

/// Every kind the model can produce: the usual and the fallback kind of each type.
pub(super) const MODEL_KINDS: KindSet = {
    let mut kinds = KindSet::EMPTY;
    let mut i = 0;
    while i < TYPES.len() {
        let (_, usual, fallback) = TYPES[i];
        kinds = kinds.with(usual);
        if let Some(fallback) = fallback {
            kinds = kinds.with(fallback);
        }
        i += 1;
    }
    kinds
};

/// The kind of a `value` the model labelled as type `type_idx`: the type's usual kind when the
/// value passes that kind's validator, else its fallback kind when that passes, else nothing.
/// So a valid IBAN under `BANK_ACCOUNT_IDENTIFIER` is an `Iban` and a number that fails the
/// checksum is a `BankAccount`; a name that is not shaped like one is dropped, and so is a phone
/// number of fewer than five digits.
pub(super) fn target(type_idx: usize, value: &str) -> Option<EntityKind> {
    let (_, usual, fallback) = TYPES.get(type_idx)?;
    if accepts(*usual, value) {
        return Some(*usual);
    }
    fallback.filter(|kind| accepts(*kind, value))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn type_index(name: &str) -> usize {
        match TYPES.iter().position(|(type_name, ..)| *type_name == name) {
            Some(i) => i,
            None => panic!("no type {name}"),
        }
    }

    #[test]
    fn types_follow_the_model_config_order() {
        assert_eq!(TYPES.len(), 35);
        assert_eq!(LABELS, 71);
        assert_eq!(COLUMNS, 36);
        assert_eq!(O, 35);
        for pair in TYPES.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} !< {}", pair[0].0, pair[1].0);
        }
        // Spot checks against `id2label`: 1/2 ACCOUNT_IDENTIFIER, 51/52 PERSON_NAME, 69/70 last.
        let type_of = |label: usize| TYPES[(label - 1) / 2].0;
        assert_eq!(type_of(1), "ACCOUNT_IDENTIFIER");
        assert_eq!(type_of(2), "ACCOUNT_IDENTIFIER");
        assert_eq!(type_of(51), "PERSON_NAME");
        assert_eq!(type_of(52), "PERSON_NAME");
        assert_eq!(type_of(70), "VEHICLE_IDENTIFIER");
    }

    #[test]
    fn every_type_has_a_distinct_usual_kind_and_every_model_only_kind_has_a_type() {
        let usual: HashSet<EntityKind> = TYPES.iter().map(|&(_, kind, _)| kind).collect();
        assert_eq!(usual.len(), TYPES.len());
        // A kind the model could never produce would be one nothing finds.
        for kind in EntityKind::ALL.into_iter().filter(|k| !k.is_watermarked()) {
            assert!(MODEL_KINDS.contains(kind), "{kind:?}");
        }
        // The kinds that need their pattern or its context rule stay with the regex detector.
        for kind in [
            EntityKind::UrlCredential,
            EntityKind::Mac,
            EntityKind::UsSsn,
            EntityKind::NlBsn,
        ] {
            assert!(!MODEL_KINDS.contains(kind), "{kind:?}");
        }
    }

    #[test]
    fn a_valid_iban_is_an_iban_and_any_other_account_number_is_a_bank_account() {
        let bank = type_index("BANK_ACCOUNT_IDENTIFIER");
        assert_eq!(target(bank, "NL91ABNA0417164300"), Some(EntityKind::Iban));
        // Bad checksum, and a plain account number.
        assert_eq!(
            target(bank, "NL91ABNA0417164301"),
            Some(EntityKind::BankAccount)
        );
        assert_eq!(target(bank, "0417164300"), Some(EntityKind::BankAccount));
    }

    #[test]
    fn typed_values_take_the_validated_kind_first() {
        assert_eq!(
            target(type_index("EMAIL_ADDRESS"), "jan.jansen@acme.nl"),
            Some(EntityKind::Email)
        );
        assert_eq!(target(type_index("EMAIL_ADDRESS"), "not an email"), None);
        assert_eq!(
            target(type_index("IP_ADDRESS"), "203.0.113.42"),
            Some(EntityKind::Ipv4)
        );
        assert_eq!(
            target(type_index("IP_ADDRESS"), "2001:db8:85a3::8a2e:370:7334"),
            Some(EntityKind::Ipv6)
        );
        assert_eq!(target(type_index("IP_ADDRESS"), "somewhere"), None);
        assert_eq!(
            target(type_index("PAYMENT_CARD"), "4111 1111 1111 1111"),
            Some(EntityKind::CreditCard)
        );
        assert_eq!(
            target(type_index("PAYMENT_CARD"), "4111 1111 1111 1112"),
            Some(EntityKind::PaymentCard)
        );
        assert_eq!(
            target(type_index("AUTH_SECRET"), "AKIAIOSFODNN7EXAMPLE"),
            Some(EntityKind::Secret)
        );
        assert_eq!(
            target(type_index("AUTH_SECRET"), "hunter2hunter2"),
            Some(EntityKind::AuthSecret)
        );
        assert_eq!(
            target(type_index("PHONE_NUMBER"), "+31 6 12345678"),
            Some(EntityKind::Phone)
        );
        // A leading-0 national number is a `Phone`; five digits and nothing more is only a number.
        assert_eq!(
            target(type_index("PHONE_NUMBER"), "0612 345 678"),
            Some(EntityKind::Phone)
        );
        assert_eq!(
            target(type_index("PHONE_NUMBER"), "12345"),
            Some(EntityKind::PhoneNumber)
        );
        assert_eq!(target(type_index("PHONE_NUMBER"), "1234"), None);
    }

    #[test]
    fn a_name_that_is_not_shaped_like_one_is_dropped() {
        let person = type_index("PERSON_NAME");
        assert_eq!(target(person, "Jan Kowalski"), Some(EntityKind::Person));
        assert_eq!(target(person, "Jan 42"), None);
        assert_eq!(target(person, "12345"), None);
        assert_eq!(target(person, ""), None);
    }

    #[test]
    fn free_text_types_map_to_their_own_kind() {
        let cases = [
            (
                "POSTAL_ADDRESS",
                "ul. Długa 5, 00-238 Warszawa",
                EntityKind::PostalAddress,
            ),
            (
                "ORGANIZATION_NAME",
                "Acme B.V.",
                EntityKind::OrganizationName,
            ),
            ("HEALTH_DATA", "diabetes", EntityKind::HealthData),
            ("LOCATION", "Amsterdam", EntityKind::Location),
            ("PERSON_ROLE_OR_TITLE", "tandarts", EntityKind::PersonRole),
            (
                "IDENTIFYING_LINK",
                "https://example.com/in/jan",
                EntityKind::IdentifyingLink,
            ),
        ];
        for (name, value, kind) in cases {
            assert_eq!(target(type_index(name), value), Some(kind), "{name}");
        }
    }

    #[test]
    fn a_link_must_look_like_one() {
        let link = type_index("IDENTIFYING_LINK");
        assert_eq!(target(link, "my favourite place"), None);
    }

    #[test]
    fn an_unknown_type_maps_to_nothing() {
        assert_eq!(target(TYPES.len(), "anything"), None);
    }
}
