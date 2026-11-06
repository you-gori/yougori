//! HMAC-SHA256 (RFC 2104 with SHA-256, as specified by RFC 4231), which authenticates
//! transfer envelopes (S2 CORE-05: "authenticated transfer/session envelope").
//!
//! S1 grants no new crate, so the construction is written here over `sha2` and pinned
//! to the RFC 4231 test vectors.

use sha2::{Digest as _, Sha256};

/// Length of an HMAC-SHA256 tag.
pub const HMAC_SHA256_TAG_BYTES: usize = 32;

/// The SHA-256 block length, RFC 2104's `B`.
const BLOCK_BYTES: usize = 64;

/// HMAC-SHA256 of `message` under `key` (RFC 2104).
///
/// A key longer than one block is hashed first; a shorter key is padded with zeros.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_SHA256_TAG_BYTES] {
    let mut block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        for (slot, byte) in block.iter_mut().zip(Sha256::digest(key)) {
            *slot = byte;
        }
    } else {
        for (slot, byte) in block.iter_mut().zip(key) {
            *slot = *byte;
        }
    }
    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for ((inner, outer), key_byte) in inner_pad.iter_mut().zip(outer_pad.iter_mut()).zip(block) {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }
    let inner_hash = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner_hash)
        .finalize()
        .into()
}

/// Compares two tags without stopping at the first difference, so the time taken does
/// not reveal how much of a forged tag was right.
pub fn tags_equal(left: &[u8; HMAC_SHA256_TAG_BYTES], right: &[u8; HMAC_SHA256_TAG_BYTES]) -> bool {
    let difference = left
        .iter()
        .zip(right)
        .fold(0u8, |accumulated, (l, r)| accumulated | (l ^ r));
    std::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag_hex(key: &[u8], message: &[u8]) -> String {
        hex::encode(hmac_sha256(key, message))
    }

    #[test]
    fn rfc_4231_test_case_1() {
        assert_eq!(
            tag_hex(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc_4231_test_case_2_key_shorter_than_the_tag() {
        assert_eq!(
            tag_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc_4231_test_case_3() {
        assert_eq!(
            tag_hex(&[0xaa; 20], &[0xdd; 50]),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc_4231_test_case_4() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        assert_eq!(key.len(), 25);
        assert_eq!(
            tag_hex(&key, &[0xcd; 50]),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc_4231_test_case_5_truncated_to_128_bits() {
        let tag = hmac_sha256(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(hex::encode(&tag[..16]), "a3b6167473100ee06e0c796c2955552b");
    }

    #[test]
    fn rfc_4231_test_case_6_key_larger_than_a_block() {
        assert_eq!(
            tag_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc_4231_test_case_7_key_and_data_larger_than_a_block() {
        assert_eq!(
            tag_hex(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm."
            ),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    /// Keys of exactly one block are used as they are; one byte more and they are hashed.
    /// Expected values were computed independently with `openssl dgst -sha256 -mac HMAC`.
    #[test]
    fn keys_at_the_block_boundary() {
        let block_key: Vec<u8> = (0u8..64).collect();
        let longer_key: Vec<u8> = (0u8..65).collect();
        assert_eq!(
            tag_hex(&block_key, b"boundary"),
            "04660fc313657aa3500078e1f2788cc4e328654092b137f946516e4d7a17adae"
        );
        assert_eq!(
            tag_hex(&longer_key, b"boundary"),
            "ea8a9678017bce7c50df43ced20cc4b112ed884969720bb2ec14e24ce582f037"
        );
        assert_eq!(
            tag_hex(&block_key, b""),
            "3499f163f48604c0b15ac89e4e7c66f314fb3b203b8ac2f564828e62f6be9d9d"
        );
    }

    #[test]
    fn tag_comparison_finds_every_single_bit_difference() {
        let tag = hmac_sha256(b"key", b"message");
        assert!(tags_equal(&tag, &tag.clone()));
        for byte in 0..HMAC_SHA256_TAG_BYTES {
            for bit in 0..8 {
                let mut forged = tag;
                forged[byte] ^= 1 << bit;
                assert!(!tags_equal(&tag, &forged), "byte {byte} bit {bit}");
            }
        }
    }
}
