//! The model's label set and how each entity type maps to a piikey [`EntityKind`].
//!
//! The model has 35 entity types in BIO tagging: logit `0` is `O` (no entity), logit `i >= 1`
//! belongs to type `(i - 1) / 2` and is its `B-` tag when `i` is odd, its `I-` tag when even. The
//! types are listed in the order of the model's `config.json`, which is alphabetical.

use crate::detect::{EntityKind, KindSet, validate::accepts};

/// Entity types, by type index.
pub(super) const TYPES: [&str; 35] = [
    "ACCOUNT_IDENTIFIER",
    "AUTH_SECRET",
    "BANK_ACCOUNT_IDENTIFIER",
    "BIOMETRIC_DATA",
    "CONTACT_HANDLE",
    "CRIMINAL_OFFENCE_DATA",
    "DATE_OF_BIRTH",
    "DEVICE_IDENTIFIER",
    "DOCUMENT_IDENTIFIER",
    "DOCUMENT_REFERENCE",
    "EMAIL_ADDRESS",
    "ETHNIC_ORIGIN",
    "FINANCIAL_AMOUNT",
    "GEO_LOCATION",
    "HEALTH_DATA",
    "IDENTIFYING_LINK",
    "IP_ADDRESS",
    "LOCATION",
    "ORGANIZATION_IDENTIFIER",
    "ORGANIZATION_NAME",
    "PAYMENT_CARD",
    "PAYMENT_CARD_SECURITY",
    "PERSON_ALIAS",
    "PERSON_ATTRIBUTE",
    "PERSON_IDENTIFIER",
    "PERSON_NAME",
    "PERSON_ROLE_OR_TITLE",
    "PHONE_NUMBER",
    "POLITICAL_OPINION",
    "POSTAL_ADDRESS",
    "PROPER_NAME",
    "RELIGION_OR_BELIEF",
    "SEXUAL_ORIENTATION",
    "TRADE_UNION_MEMBERSHIP",
    "VEHICLE_IDENTIFIER",
];

/// Logits per token: `O` plus a `B-` and an `I-` tag for each type.
pub(super) const LABELS: usize = 1 + 2 * TYPES.len();

/// Columns of a per-type distribution: one per type, then `O` last.
pub(super) const COLUMNS: usize = TYPES.len() + 1;

/// Column of `O` in a per-type distribution.
pub(super) const O: usize = TYPES.len();

/// What a type becomes: the kind its values usually have, and one to use when they fail that
/// kind's validator. Aligned with [`TYPES`].
const KINDS: [(EntityKind, Option<EntityKind>); 35] = [
    (EntityKind::AccountId, None),
    (EntityKind::Secret, Some(EntityKind::AuthSecret)),
    (EntityKind::Iban, Some(EntityKind::BankAccount)),
    (EntityKind::BiometricData, None),
    (EntityKind::ContactHandle, None),
    (EntityKind::CriminalOffence, None),
    (EntityKind::DateOfBirth, None),
    (EntityKind::DeviceId, None),
    (EntityKind::DocumentId, None),
    (EntityKind::DocumentReference, None),
    (EntityKind::Email, None),
    (EntityKind::EthnicOrigin, None),
    (EntityKind::FinancialAmount, None),
    (EntityKind::GeoLocation, None),
    (EntityKind::HealthData, None),
    (EntityKind::IdentifyingLink, None),
    (EntityKind::Ipv4, Some(EntityKind::Ipv6)),
    (EntityKind::Location, None),
    (EntityKind::OrganizationId, None),
    (EntityKind::OrganizationName, None),
    (EntityKind::CreditCard, Some(EntityKind::PaymentCard)),
    (EntityKind::CardSecurity, None),
    (EntityKind::PersonAlias, None),
    (EntityKind::PersonAttribute, None),
    (EntityKind::PersonIdentifier, None),
    (EntityKind::Person, None),
    (EntityKind::PersonRole, None),
    (EntityKind::Phone, Some(EntityKind::PhoneNumber)),
    (EntityKind::PoliticalOpinion, None),
    (EntityKind::PostalAddress, None),
    (EntityKind::ProperName, None),
    (EntityKind::ReligionOrBelief, None),
    (EntityKind::SexualOrientation, None),
    (EntityKind::TradeUnion, None),
    (EntityKind::VehicleId, None),
];

/// Every kind the model can produce: the eight it shares with the regex table and the kinds
/// from code 13 up that only it finds.
pub(super) const MODEL_KINDS: KindSet = KindSet::from_bits(!0 << 13)
    .with(EntityKind::Person)
    .with(EntityKind::Email)
    .with(EntityKind::Ipv4)
    .with(EntityKind::Ipv6)
    .with(EntityKind::Phone)
    .with(EntityKind::CreditCard)
    .with(EntityKind::Iban)
    .with(EntityKind::Secret);

/// The kind of a `value` the model labelled as type `type_idx`: the type's usual kind when the
/// value passes that kind's validator, else its fallback kind when that passes, else nothing.
/// So a valid IBAN under `BANK_ACCOUNT_IDENTIFIER` is an `Iban` and a number that fails the
/// checksum is a `BankAccount`; a name that is not shaped like one is dropped.
pub(super) fn target(type_idx: usize, value: &str) -> Option<EntityKind> {
    let (usual, fallback) = KINDS.get(type_idx)?;
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
        match TYPES.iter().position(|t| *t == name) {
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
            assert!(pair[0] < pair[1], "{} !< {}", pair[0], pair[1]);
        }
        // Spot checks against `id2label`: 1/2 ACCOUNT_IDENTIFIER, 51/52 PERSON_NAME, 69/70 last.
        let type_of = |label: usize| TYPES[(label - 1) / 2];
        assert_eq!(type_of(1), "ACCOUNT_IDENTIFIER");
        assert_eq!(type_of(2), "ACCOUNT_IDENTIFIER");
        assert_eq!(type_of(51), "PERSON_NAME");
        assert_eq!(type_of(52), "PERSON_NAME");
        assert_eq!(type_of(70), "VEHICLE_IDENTIFIER");
    }

    #[test]
    fn every_type_has_a_distinct_usual_kind_and_the_model_set_covers_them() {
        let usual: HashSet<EntityKind> = KINDS.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(usual.len(), TYPES.len());
        for (usual, fallback) in KINDS {
            assert!(MODEL_KINDS.contains(usual));
            if let Some(fallback) = fallback {
                assert!(MODEL_KINDS.contains(fallback));
            }
        }
        // Everything from code 13 up is the model's; of the others only the shared eight.
        for kind in EntityKind::ALL {
            let shared = matches!(
                kind,
                EntityKind::Person
                    | EntityKind::Email
                    | EntityKind::Ipv4
                    | EntityKind::Ipv6
                    | EntityKind::Phone
                    | EntityKind::CreditCard
                    | EntityKind::Iban
                    | EntityKind::Secret
            );
            assert_eq!(
                MODEL_KINDS.contains(kind),
                shared || kind as u8 >= 13,
                "{kind:?}"
            );
        }
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
