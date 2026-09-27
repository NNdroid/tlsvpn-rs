#!/usr/bin/env python3
from pathlib import Path
p = Path('src/crypto.rs')
s = p.read_text()
if 'go_aead_known_answer_vectors_match' in s:
    raise SystemExit('already added')
s += r'''

#[cfg(test)]
mod go_aead_known_answer_vectors {
    use super::*;

    #[test]
    fn go_aead_known_answer_vectors_match() {
        let psk = "cross-language-domain-vector";
        let salt = hex::decode("0011223344556677").unwrap();
        let plain = hex::decode("65746865726e65742d7061796c6f6164").unwrap();
        let seq = 0x01020304u32;
        let vectors = [
            (ENC_ALGO_GCM, "data", "6b7d896fdb4baed8b0775ea1ee38aba4097de242650d322e5a3a6775c4f07c8b"),
            (ENC_ALGO_GCM, "fec", "108721428cf9bacbba87a5b5ca28423d6a4af4d23d0c3338a676c8a584088b56"),
            (ENC_ALGO_GCM128, "data", "aca23415a7f2daba74e4b585171732e8970a3346125a0ce7ff4a3681c5dc098b"),
            (ENC_ALGO_GCM128, "fec", "46276ec436392e1ea49e5f00726d9079703524f0b623df8e1ccf582216a12375"),
            (ENC_ALGO_CHACHA20, "data", "720c46b7bdec71fd38fbde65073f9bab7b0f40fa6bed33a973127531ce7f14d5"),
            (ENC_ALGO_CHACHA20, "fec", "ba223e31950d27fe521b6629df45160df251cc361c649e3e7654bf6be23bd7b0"),
            (ENC_ALGO_XCHACHA20, "data", "dab95dcd60c7526fea52c69928fcce4fe639b2d03e02e543dc5158522649d397"),
            (ENC_ALGO_XCHACHA20, "fec", "47fa22c20f87f0b4e46db710bace56dfab35bccf7ed17ca820ad3b4f35dad9d8"),
        ];
        for (algo, domain, want) in vectors {
            let cipher = InnerCipher::domain_for_algo(psk, &salt, domain, algo).unwrap();
            let mut wire = vec![0u8; plain.len() + GCM_TAG_SIZE];
            wire[..plain.len()].copy_from_slice(&plain);
            let wire_len = wire.len() as u32;
            cipher.seal_in_place(&mut wire, plain.len(), seq, wire_len);
            assert_eq!(hex::encode(&wire), want, "algo={} domain={}", algo, domain);
        }
    }
}
'''
p.write_text(s)
