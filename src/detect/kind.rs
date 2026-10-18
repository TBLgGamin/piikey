//! Entity kinds and detected spans.

/// A PII category. Discriminants are the vault wire format: never renumber.
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
}

impl EntityKind {
    /// Every kind, in detection priority order.
    pub const ALL: [Self; 11] = [
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
        }
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
            _ => return None,
        })
    }
}

/// A detected value: byte offsets into UTF-8 text. Both ends sit on ASCII
/// bytes, so they are always char boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub kind: EntityKind,
}

#[cfg(test)]
mod tests {
    use super::EntityKind;

    #[test]
    fn wire_codes_round_trip() {
        for kind in EntityKind::ALL {
            assert_eq!(EntityKind::from_u8(kind as u8), Some(kind));
        }
        assert_eq!(EntityKind::from_u8(0), None);
        assert_eq!(EntityKind::from_u8(12), None);
    }
}
