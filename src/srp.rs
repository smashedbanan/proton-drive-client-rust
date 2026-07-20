use sha2::{Digest, Sha512};

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
