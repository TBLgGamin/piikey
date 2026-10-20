//! Entity kinds and detected spans.

/// A PII category. Discriminants are the vault wire format: never renumber.
/// The vault indexes kinds by `kind as u8 - 1`, so codes stay dense.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum EntityKind {
    Secret = 1,
    UrlCredential = 2,
    Email = 3,
    Iban = 4,
    CreditCard = 5,
    Ipv6 = 6,
    Mac = 7,
    Ipv4 = 8,
    UsSsn = 9,
    NlBsn = 10,
    Phone = 11,
    /// A personal name, found by the detection model.
    Person = 12,
    /// An alias or nickname.
    PersonAlias = 13,
    /// A personal identification number.
    PersonIdentifier = 14,
    /// A personal trait (age, gender, appearance).
    PersonAttribute = 15,
    /// A role or job title.
    PersonRole = 16,
    /// A date of birth.
    DateOfBirth = 17,
    /// A phone number the phone pattern did not confirm.
    PhoneNumber = 18,
    /// A social media or chat handle.
    ContactHandle = 19,
    /// A postal address; may span lines.
    PostalAddress = 20,
    /// A place name.
    Location = 21,
    /// Geographic coordinates.
    GeoLocation = 22,
    /// A device identifier.
    DeviceId = 23,
    /// A link that identifies a person.
    IdentifyingLink = 24,
    /// An account identifier or username.
    AccountId = 25,
    /// A password or secret the secret pattern did not confirm.
    AuthSecret = 26,
    /// A bank account that is not a valid IBAN.
    BankAccount = 27,
    /// A card number that fails the Luhn check.
    PaymentCard = 28,
    /// A card security code.
    CardSecurity = 29,
    /// An amount of money.
    FinancialAmount = 30,
    /// A document number (passport, licence).
    DocumentId = 31,
    /// A reference to a document (case or file number).
    DocumentReference = 32,
    /// A licence plate or VIN.
    VehicleId = 33,
    /// An organization name.
    OrganizationName = 34,
    /// An organization identifier (company or tax number).
    OrganizationId = 35,
    /// Another proper name (product, brand).
    ProperName = 36,
    /// Health data.
    HealthData = 37,
    /// Biometric data.
    BiometricData = 38,
    /// Racial or ethnic origin.
    EthnicOrigin = 39,
    /// A political opinion.
    PoliticalOpinion = 40,
    /// A religion or belief.
    ReligionOrBelief = 41,
    /// Sexual orientation.
    SexualOrientation = 42,
    /// Trade union membership.
    TradeUnion = 43,
    /// Criminal offence data.
    CriminalOffence = 44,
}

impl EntityKind {
    /// Every kind: the patterned ones in detection priority order, then the rest by code.
    pub const ALL: [Self; 44] = [
        Self::Secret,
        Self::UrlCredential,
        Self::Email,
        Self::Iban,
        Self::CreditCard,
        Self::Ipv6,
        Self::Mac,
        Self::Ipv4,
        Self::UsSsn,
        Self::NlBsn,
        Self::Phone,
        Self::Person,
        Self::PersonAlias,
        Self::PersonIdentifier,
        Self::PersonAttribute,
        Self::PersonRole,
        Self::DateOfBirth,
        Self::PhoneNumber,
        Self::ContactHandle,
        Self::PostalAddress,
        Self::Location,
        Self::GeoLocation,
        Self::DeviceId,
        Self::IdentifyingLink,
        Self::AccountId,
        Self::AuthSecret,
        Self::BankAccount,
        Self::PaymentCard,
        Self::CardSecurity,
        Self::FinancialAmount,
        Self::DocumentId,
        Self::DocumentReference,
        Self::VehicleId,
        Self::OrganizationName,
        Self::OrganizationId,
        Self::ProperName,
        Self::HealthData,
        Self::BiometricData,
        Self::EthnicOrigin,
        Self::PoliticalOpinion,
        Self::ReligionOrBelief,
        Self::SexualOrientation,
        Self::TradeUnion,
        Self::CriminalOffence,
    ];

    /// Lowercase snake-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::UrlCredential => "url_credential",
            Self::Email => "email",
            Self::Iban => "iban",
            Self::CreditCard => "credit_card",
            Self::Ipv6 => "ipv6",
            Self::Mac => "mac",
            Self::Ipv4 => "ipv4",
            Self::UsSsn => "us_ssn",
            Self::NlBsn => "nl_bsn",
            Self::Phone => "phone",
            Self::Person => "person",
            Self::PersonAlias => "person_alias",
            Self::PersonIdentifier => "person_identifier",
            Self::PersonAttribute => "person_attribute",
            Self::PersonRole => "person_role",
            Self::DateOfBirth => "date_of_birth",
            Self::PhoneNumber => "phone_number",
            Self::ContactHandle => "contact_handle",
            Self::PostalAddress => "postal_address",
            Self::Location => "location",
            Self::GeoLocation => "geo_location",
            Self::DeviceId => "device_identifier",
            Self::IdentifyingLink => "identifying_link",
            Self::AccountId => "account_identifier",
            Self::AuthSecret => "auth_secret",
            Self::BankAccount => "bank_account",
            Self::PaymentCard => "payment_card",
            Self::CardSecurity => "card_security",
            Self::FinancialAmount => "financial_amount",
            Self::DocumentId => "document_identifier",
            Self::DocumentReference => "document_reference",
            Self::VehicleId => "vehicle_identifier",
            Self::OrganizationName => "organization_name",
            Self::OrganizationId => "organization_identifier",
            Self::ProperName => "proper_name",
            Self::HealthData => "health_data",
            Self::BiometricData => "biometric_data",
            Self::EthnicOrigin => "ethnic_origin",
            Self::PoliticalOpinion => "political_opinion",
            Self::ReligionOrBelief => "religion_or_belief",
            Self::SexualOrientation => "sexual_orientation",
            Self::TradeUnion => "trade_union",
            Self::CriminalOffence => "criminal_offence",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// Inverse of `kind as u8`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Secret,
            2 => Self::UrlCredential,
            3 => Self::Email,
            4 => Self::Iban,
            5 => Self::CreditCard,
            6 => Self::Ipv6,
            7 => Self::Mac,
            8 => Self::Ipv4,
            9 => Self::UsSsn,
            10 => Self::NlBsn,
            11 => Self::Phone,
            12 => Self::Person,
            13 => Self::PersonAlias,
            14 => Self::PersonIdentifier,
            15 => Self::PersonAttribute,
            16 => Self::PersonRole,
            17 => Self::DateOfBirth,
            18 => Self::PhoneNumber,
            19 => Self::ContactHandle,
            20 => Self::PostalAddress,
            21 => Self::Location,
            22 => Self::GeoLocation,
            23 => Self::DeviceId,
            24 => Self::IdentifyingLink,
            25 => Self::AccountId,
            26 => Self::AuthSecret,
            27 => Self::BankAccount,
            28 => Self::PaymentCard,
            29 => Self::CardSecurity,
            30 => Self::FinancialAmount,
            31 => Self::DocumentId,
            32 => Self::DocumentReference,
            33 => Self::VehicleId,
            34 => Self::OrganizationName,
            35 => Self::OrganizationId,
            36 => Self::ProperName,
            37 => Self::HealthData,
            38 => Self::BiometricData,
            39 => Self::EthnicOrigin,
            40 => Self::PoliticalOpinion,
            41 => Self::ReligionOrBelief,
            42 => Self::SexualOrientation,
            43 => Self::TradeUnion,
            44 => Self::CriminalOffence,
            _ => return None,
        })
    }

    /// Found by the regex pattern table.
    #[must_use]
    pub const fn is_patterned(self) -> bool {
        (self as u8) <= 11
    }

    /// Found back in proxied text by exact lookup of the issued proxies
    /// (no pattern finds them).
    #[must_use]
    pub const fn is_listed(self) -> bool {
        !self.is_patterned()
    }

    /// Proxies carry a watermark the deanonymizer checks.
    #[must_use]
    pub const fn is_watermarked(self) -> bool {
        (self as u8) <= 12
    }
}

/// A set of kinds; bit `kind as u8` is set for each member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindSet(u64);

impl KindSet {
    /// Every kind.
    pub const ALL: Self = Self(((1u64 << 45) - 1) & !1);
    /// No kind.
    pub const EMPTY: Self = Self(0);

    /// Builds a set from its raw bits (bit `kind as u8` per member; others ignored).
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, kind: EntityKind) -> bool {
        self.0 & (1 << kind as u8) != 0
    }

    #[must_use]
    pub const fn with(self, kind: EntityKind) -> Self {
        Self(self.0 | (1 << kind as u8))
    }

    #[must_use]
    pub const fn without(self, kind: EntityKind) -> Self {
        Self(self.0 & !(1 << kind as u8))
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl FromIterator<EntityKind> for KindSet {
    fn from_iter<I: IntoIterator<Item = EntityKind>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

/// A detected value: byte offsets into UTF-8 text, always on char
/// boundaries (names may start or end with non-ASCII letters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub kind: EntityKind,
}

#[cfg(test)]
mod tests {
    use super::{EntityKind, KindSet};

    #[test]
    fn wire_codes_round_trip() {
        for kind in EntityKind::ALL {
            assert_eq!(EntityKind::from_u8(kind as u8), Some(kind));
            assert_eq!(EntityKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(EntityKind::from_u8(0), None);
        assert_eq!(EntityKind::from_u8(45), None);
        assert_eq!(EntityKind::parse("bogus"), None);
    }

    #[test]
    fn codes_are_dense_and_listed_once() {
        let mut codes: Vec<u8> = EntityKind::ALL.iter().map(|&k| k as u8).collect();
        codes.sort_unstable();
        assert_eq!(codes, (1..=44).collect::<Vec<u8>>());
    }

    #[test]
    fn kind_sets_hold_exactly_their_members() {
        let all: KindSet = EntityKind::ALL.into_iter().collect();
        assert_eq!(all, KindSet::ALL);
        let some = KindSet::ALL.without(EntityKind::Email);
        assert!(!some.contains(EntityKind::Email));
        assert!(some.contains(EntityKind::CriminalOffence));
        assert!(KindSet::EMPTY.is_empty());
        assert!(!KindSet::EMPTY.intersects(KindSet::ALL));
        assert!(KindSet::EMPTY.with(EntityKind::Person).intersects(some));
        assert_eq!(KindSet::from_bits(u64::MAX), KindSet::ALL);
    }
}
