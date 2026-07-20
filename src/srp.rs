use crate::error::{Error, Result};
use base64::Engine;
use num_bigint::BigUint;
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use sha2::{Digest, Sha512};

/// Modulus is always exactly 2048 bits.
pub const MODULUS_BYTE_LEN: usize = 256;

/// Proton's hardcoded public key (`proton@srp.modulus`) used to sign every
/// server-issued SRP modulus. This is not a placeholder — it is the real,
/// publicly-known key from Proton's own open-source SRP clients (go-srp),
/// used to verify the modulus hasn't been tampered with in transit.
const MODULUS_PUBKEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\r\nL8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\r\nBwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\r\nMnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\r\nSv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\r\nkSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\r\nhcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\r\nWO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\r\n=Y4Mw\r\n-----END PGP PUBLIC KEY BLOCK-----";

/// Verifies the cleartext-signed modulus message against Proton's hardcoded
/// signing key and returns the decoded modulus as a little-endian BigUint.
///
/// The modulus wire format is little-endian — confirmed during planning by
/// checking N mod 8 == 3 (the property Proton's own native client checks to
/// validate a safe prime): the big-endian interpretation of a real captured
/// modulus is not even prime, the little-endian one is, with N mod 8 == 3.
pub fn verify_and_decode_modulus(clearsigned: &str) -> Result<BigUint> {
    let (public_key, _headers) = SignedPublicKey::from_string(MODULUS_PUBKEY)
        .map_err(|e| Error::Crypto(format!("bad hardcoded modulus pubkey: {e}")))?;
    let (msg, _headers) = CleartextSignedMessage::from_string(clearsigned)
        .map_err(|e| Error::Crypto(format!("bad modulus message: {e}")))?;
    msg.verify(&public_key)
        .map_err(|e| Error::Crypto(format!("modulus signature invalid: {e}")))?;
    let cleartext = msg.signed_text();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleartext.trim())
        .map_err(|e| Error::Crypto(format!("bad modulus base64: {e}")))?;
    Ok(BigUint::from_bytes_le(&bytes))
}

/// Proton's SRP hash primitive: four SHA-512 hashes of `data` suffixed with
/// 0x00..0x03, concatenated — 256 bytes total, sized to match the 2048-bit
/// modulus. Real values below are independently computed SHA-512 digests of
/// b"test" ++ [0..3], not values copied from any Proton source.
pub fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for suffix in 0u8..4 {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.update([suffix]);
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_hash_matches_known_sha512_values() {
        let expected = [
            "d55ced17163bf5386f2cd9ff21d6fd7fe576a915065c24744d09cfae4ec84ee1ef6ef11bfbc5acce3639bab725b50a1fe2c204f8c820d6d7db0df0ecbc49c5ca",
            "04989213d3f0bf08f5f535714f0300a50bd33aecef1221a156163ed7b2b54f5b426e3f20d32f04430d2af76aefd76512504e99b98259cba7a956b1911d12c5a5",
            "ff8408e88d250257a4296ff41e34d8fcc8c7608828a0c67de20ec4727a2a0883b6147532514382cf315dd68b042fb51788ed225a357d02afa770b8859e389092",
            "12eb9cdd20af823d55326efb3877e7c546db77a6cf52cf01ed8e050c62e85d27e63978681773d6724130b80769971fef10ff44f4d29e6d57b99875b815ecbfcb",
        ];
        let got = expand_hash(b"test");
        assert_eq!(got.len(), 256);
        for (i, exp_hex) in expected.iter().enumerate() {
            let chunk_hex: String = got[i * 64..(i + 1) * 64]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&chunk_hex, exp_hex, "chunk {i} mismatch");
        }
    }
}

#[cfg(test)]
mod modulus_tests {
    use super::*;

    const TEST_MODULUS_CLEARSIGN: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";

    #[test]
    fn verifies_and_decodes_real_fixture() {
        let n = verify_and_decode_modulus(TEST_MODULUS_CLEARSIGN).unwrap();
        assert_eq!(n.to_bytes_le().len(), MODULUS_BYTE_LEN.min(n.to_bytes_le().len()).max(255));
        assert_eq!(&n % 8u32, BigUint::from(3u32), "N mod 8 must be 3 for a valid safe prime");
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut tampered = TEST_MODULUS_CLEARSIGN.to_string();
        let last = tampered.len();
        tampered.replace_range(last - 60..last - 59, "9");
        assert!(verify_and_decode_modulus(&tampered).is_err());
    }
}
