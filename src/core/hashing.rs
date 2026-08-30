//! Canonical encoding, the one unambiguous preimage this chain hashes and signs
//!
//! A preimage pasted together with a separator is not a function of the fields
//! it was built from, only of the string that came out. With
//! `format!("{}|{}", sender, recipient)` the pair `("a|b", "c")` and the pair
//! `("a", "b|c")` produce the identical preimage: two different transactions,
//! one hash, and one signature that covers both. Escaping the separator only
//! moves the ambiguity into the escaping.
//!
//! [`CanonicalEncoding`] removes it instead. Every field is written as its
//! length, big-endian in eight bytes, followed by exactly that many bytes, so
//! the encoding can be parsed back into the field list it was built from and no
//! field can borrow bytes from its neighbour. The first field is always a domain
//! tag, which keeps a preimage produced in one context, a block header, from
//! ever being a valid preimage in another, a signature.
//!
//! ```text
//! encoding := field*
//! field    := u64 length (big-endian) || `length` bytes
//! ```
//!
//! The encoding is versioned through its domain tag. Changing what a field means
//! means minting a new tag rather than reusing an old one, so an old signature
//! can never be read under new rules.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

/// Domain tag for the transaction hash, the leaf the Merkle tree commits to.
pub(crate) const TRANSACTION_HASH_DOMAIN: &str = "rustchain.transaction.hash.v1";

/// Domain tag for the bytes a transaction signature covers.
pub(crate) const TRANSACTION_SIGNING_DOMAIN: &str = "rustchain.transaction.signature.v1";

/// Domain tag for the block header, the preimage proof-of-work searches over.
pub(crate) const BLOCK_HASH_DOMAIN: &str = "rustchain.block.header.v1";

/// Domain tag for a Merkle leaf.
pub(crate) const MERKLE_LEAF_DOMAIN: &str = "rustchain.merkle.leaf.v1";

/// Domain tag for the root of an empty Merkle tree.
///
/// In its own domain so the empty-tree root can never equal a leaf, an internal
/// node or the padding sentinel: reusing the leaf domain let the empty root
/// collide with the leaf of a chosen value.
pub(crate) const MERKLE_EMPTY_DOMAIN: &str = "rustchain.merkle.empty.v1";

/// Domain tag for a Merkle internal node.
pub(crate) const MERKLE_NODE_DOMAIN: &str = "rustchain.merkle.node.v1";

/// Domain tag for the constant that pads an odd Merkle level.
pub(crate) const MERKLE_PADDING_DOMAIN: &str = "rustchain.merkle.padding.v1";

/// A canonical, length-prefixed encoding under construction.
///
/// Built field by field and finished with either [`Self::hash_hex`], the
/// SHA-256 of the encoding, or [`Self::into_bytes`], for the callers that hand
/// the preimage itself to a signature.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalEncoding {
    bytes: Vec<u8>,
}

impl CanonicalEncoding {
    /// Start an encoding in `domain`, which is written as the first field.
    pub(crate) fn new(domain: &str) -> Self {
        let mut encoding = Self {
            bytes: Vec::with_capacity(256),
        };
        encoding.push_field(domain.as_bytes());
        encoding
    }

    /// Write one length-prefixed field.
    fn push_field(&mut self, field: &[u8]) {
        self.bytes
            .extend_from_slice(&(field.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(field);
    }

    /// Append a text field.
    pub(crate) fn text(mut self, value: &str) -> Self {
        self.push_field(value.as_bytes());
        self
    }

    /// Append an optional text field.
    ///
    /// Presence is part of the field, so an absent value and an empty one are
    /// different preimages: a transaction carrying no signature must not hash
    /// like one carrying the empty signature.
    pub(crate) fn optional_text(mut self, value: Option<&str>) -> Self {
        match value {
            Some(text) => {
                let mut field = Vec::with_capacity(text.len() + 1);
                field.push(1u8);
                field.extend_from_slice(text.as_bytes());
                self.push_field(&field);
            }
            None => self.push_field(&[0u8]),
        }
        self
    }

    /// Append an unsigned integer field, fixed at eight big-endian bytes.
    pub(crate) fn integer(mut self, value: u64) -> Self {
        self.push_field(&value.to_be_bytes());
        self
    }

    /// Append a boolean field.
    pub(crate) fn flag(mut self, value: bool) -> Self {
        self.push_field(&[u8::from(value)]);
        self
    }

    /// Append a timestamp, as a second count and the nanoseconds within it.
    ///
    /// Deliberately not `timestamp_nanos_opt`: that is `None` outside
    /// 1677..=2262, and any fallback collapses every out-of-range instant onto
    /// one value, an ambiguity of exactly the kind this module exists to
    /// remove. A `DateTime<Utc>` is always exactly a second count plus a
    /// subsecond remainder, for every value it can hold.
    pub(crate) fn time(mut self, value: &DateTime<Utc>) -> Self {
        let mut field = [0u8; 12];
        field[..8].copy_from_slice(&value.timestamp().to_be_bytes());
        field[8..].copy_from_slice(&value.timestamp_subsec_nanos().to_be_bytes());
        self.push_field(&field);
        self
    }

    /// The encoded bytes, for a caller that signs the preimage itself.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The SHA-256 of the encoding, hex-encoded.
    pub(crate) fn hash_hex(self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_cannot_borrow_bytes_from_its_neighbour() {
        // The whole point: under a separator-joined preimage these two are the
        // same string, so the two field lists share a hash and a signature.
        let split_left = CanonicalEncoding::new("domain").text("a|b").text("c");
        let split_right = CanonicalEncoding::new("domain").text("a").text("b|c");

        assert_ne!(split_left.hash_hex(), split_right.hash_hex());
    }

    #[test]
    fn an_empty_field_is_not_an_absent_one() {
        let empty = CanonicalEncoding::new("domain").optional_text(Some(""));
        let absent = CanonicalEncoding::new("domain").optional_text(None);

        assert_ne!(empty.hash_hex(), absent.hash_hex());
    }

    #[test]
    fn the_domain_separates_identical_field_lists() {
        // A block header preimage must never be a valid signature preimage.
        let one = CanonicalEncoding::new("rustchain.a.v1").text("payload");
        let other = CanonicalEncoding::new("rustchain.b.v1").text("payload");

        assert_ne!(one.hash_hex(), other.hash_hex());
    }

    #[test]
    fn timestamps_outside_the_nanosecond_range_stay_distinct() {
        // `timestamp_nanos_opt` returns None for both of these, so any encoding
        // built on it would hash the two identically.
        let earliest = CanonicalEncoding::new("domain").time(&DateTime::<Utc>::MIN_UTC);
        let latest = CanonicalEncoding::new("domain").time(&DateTime::<Utc>::MAX_UTC);

        assert!(DateTime::<Utc>::MIN_UTC.timestamp_nanos_opt().is_none());
        assert!(DateTime::<Utc>::MAX_UTC.timestamp_nanos_opt().is_none());
        assert_ne!(earliest.hash_hex(), latest.hash_hex());
    }

    #[test]
    fn subsecond_precision_is_preserved() {
        let base = DateTime::UNIX_EPOCH;
        let later = base + chrono::Duration::nanoseconds(1);

        assert_ne!(
            CanonicalEncoding::new("domain").time(&base).hash_hex(),
            CanonicalEncoding::new("domain").time(&later).hash_hex()
        );
    }

    #[test]
    fn the_encoding_is_length_prefixed() {
        let encoded = CanonicalEncoding::new("ab").text("cde").into_bytes();

        assert_eq!(
            encoded,
            [
                &2u64.to_be_bytes()[..],
                b"ab",
                &3u64.to_be_bytes()[..],
                b"cde"
            ]
            .concat()
        );
    }
}
