#![allow(non_snake_case)]
use curv_kzen::elliptic::curves::secp256_k1;
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::ed25519;
use curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::*;
use multi_party_eddsa::protocols::thresholdsig;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;
use neon::register_module;
use neon_serde::export;

export! {
    fn ed25519_create_key(index: usize) -> thresholdsig::Keys {
        thresholdsig::Keys::phase1_create(index)
    }

    fn ed25519_phase1_broadcast(key: thresholdsig::Keys) -> (thresholdsig::KeyGenBroadcastMessage1, BigInt) {
        key.phase1_broadcast()
    }

    fn ed25519_phase1_verify_com_phase2_distribute(
        key: thresholdsig::Keys,
        params: thresholdsig::Parameters,
        blind_vec: Vec<BigInt>,
        y_vec: Vec<ed25519::GE>,
        bc1_vec: Vec<thresholdsig::KeyGenBroadcastMessage1>,
        parties: Vec<usize>
    ) -> Result<(VerifiableSS<ed25519::GE>, Vec<ed25519::FE>, usize), multi_party_eddsa::Error> {
        key.phase1_verify_com_phase2_distribute(&params, &blind_vec, &y_vec, &bc1_vec, &parties)
    }

    fn ed25519_phase2_verify_vss_construct_keypair(
        key: thresholdsig::Keys,
        params: thresholdsig::Parameters,
        y_vec: Vec<ed25519::GE>,
        secret_shares_vec: Vec<ed25519::FE>,
        vss_scheme_vec: Vec<VerifiableSS<ed25519::GE>>
    ) -> Result<thresholdsig::SharedKeys, multi_party_eddsa::Error> {
        key.phase2_verify_vss_construct_keypair(&params, &y_vec, &secret_shares_vec, &vss_scheme_vec, &key.party_index)
    }

    fn ed25519_private_key(vss_scheme_vec: Vec<VerifiableSS<ed25519::GE>>, xs: Vec<ed25519::FE>, us: Vec<ed25519::FE>, indices: Vec<usize>) -> (ed25519::FE, ed25519::FE) {
        let v = vss_scheme_vec[0].clone();
        let x = v.reconstruct(&indices, &xs);
        let x2 = us.iter()
            .fold(ed25519::FE::zero(), |acc, x| acc + x);
        (x, x2)
    }

    fn ed25519_create_ephermeral_key(key: thresholdsig::Keys, message: Vec<u8>) -> thresholdsig::EphemeralKey {
        thresholdsig::EphemeralKey::ephermeral_key_create_from_deterministic_secret(&key, &message, key.party_index)
    }

    fn ed25519_ephermeral_phase1_broadcast(key: thresholdsig::EphemeralKey) -> (thresholdsig::KeyGenBroadcastMessage1, BigInt) {
        key.phase1_broadcast()
    }

    fn ed25519_ephermeral_phase1_verify_com_phase2_distribute(
        key: thresholdsig::EphemeralKey,
        params: thresholdsig::Parameters,
        blind_vec: Vec<BigInt>,
        Rs: Vec<ed25519::GE>,
        bc1_vec: Vec<thresholdsig::KeyGenBroadcastMessage1>,
        parties: Vec<usize>
    ) -> Result<(VerifiableSS<ed25519::GE>, Vec<ed25519::FE>, usize), multi_party_eddsa::Error> {
        key.phase1_verify_com_phase2_distribute(&params, &blind_vec, &Rs, &bc1_vec, &parties)
    }

    fn ed25519_ephermeral_phase2_verify_vss_construct_keypair(
        key: thresholdsig::EphemeralKey,
        params: thresholdsig::Parameters,
        rs: Vec<ed25519::GE>,
        secret_shares_vec: Vec<ed25519::FE>,
        vss_scheme_vec: Vec<VerifiableSS<ed25519::GE>>,
        index: usize
    ) -> Result<thresholdsig::EphemeralSharedKeys, multi_party_eddsa::Error> {
        key.phase2_verify_vss_construct_keypair(&params, &rs, &secret_shares_vec, &vss_scheme_vec, &index)
    }

    fn ed25519_compute_local_sig(message: Vec<u8>, eph_shared_key: thresholdsig::EphemeralSharedKeys, shared_key: thresholdsig::SharedKeys) -> thresholdsig::LocalSig {
        thresholdsig::LocalSig::compute(&message, &eph_shared_key, &shared_key)
    }

    fn ed25519_verify_local_sig(gamma_vec: Vec<thresholdsig::LocalSig>, parties_index_vec: Vec<usize>, vss: Vec<VerifiableSS<ed25519::GE>>, vss_eph: Vec<VerifiableSS<ed25519::GE>>) -> Result<VerifiableSS<ed25519::GE>, multi_party_eddsa::Error> {
        thresholdsig::LocalSig::verify_local_sigs(
            &gamma_vec,
            &parties_index_vec,
            &vss,
            &vss_eph,
        )
    }

    fn ed25519_generate_signature(vss_sum_local_sigs: VerifiableSS<ed25519::GE>, local_sig_vec: Vec<thresholdsig::LocalSig>, parties_index_vec: Vec<usize>, R: ed25519::GE) -> thresholdsig::Signature {
        thresholdsig::Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, R)
    }

    fn ed25519_verify_signature(s: thresholdsig::Signature, message: Vec<u8>, public_key: ed25519::GE) -> Result<(), multi_party_eddsa::Error> {
        s.verify(&message, &public_key)
    }

    fn ed25519_mul(p: ed25519::GE, s: ed25519::FE) -> ed25519::GE {
        p * s
    }

    fn ed25519_construct_private(vss_scheme: VerifiableSS<ed25519::GE>, indices: Vec<usize>, xs: Vec<ed25519::FE>) -> ed25519::FE {
        vss_scheme.reconstruct(&indices, &xs)
    }

    fn ed25519_to_public_key(s: ed25519::FE) -> ed25519::GE {
        ed25519::GE::generator() * s
    }

    fn secp256k1_keygen_stage1(input: KeyGenStage1Input) -> KeyGenStage1Result {
        keygen_stage1(&input)
    }

    fn secp256k1_keygen_stage2(input: KeyGenStage2Input) -> Result<KeyGenStage2Result, ErrorType> {
        keygen_stage2(&input)
    }

    fn secp256k1_keygen_stage3(input: KeyGenStage3Input) -> Result<KeyGenStage3Result, ErrorType> {
        keygen_stage3(&input)
    }

    fn secp256k1_keygen_stage4(input: KeyGenStage4Input) -> Result<(), ErrorType> {
        keygen_stage4(&input)
    }

    fn secp256k1_sign_stage1(input: SignStage1Input) -> SignStage1Result {
        sign_stage1(&input)
    }

    fn secp256k1_sign_stage2(input: SignStage2Input) -> Result<SignStage2Result, ErrorType> {
        sign_stage2(&input)
    }

    fn secp256k1_sign_stage3(input: SignStage3Input) -> Result<SignStage3Result, multi_party_ecdsa::Error> {
        sign_stage3(&input)
    }

    fn secp256k1_sign_stage4(input: SignStage4Input) -> Result<SignStage4Result, ErrorType> {
        sign_stage4(&input)
    }

    fn secp256k1_sign_stage5(input: SignStage5Input) -> Result<SignStage5Result, ErrorType> {
        sign_stage5(&input)
    }

    fn secp256k1_sign_stage6(input: SignStage6Input) -> Result<SignStage6Result, ErrorType> {
        sign_stage6(&input)
    }

    fn secp256k1_sign_stage7(input: SignStage7Input) -> Result<SignStage7Result, ErrorType> {
        sign_stage7(&input)
    }

    fn secp256k1_phase3_reconstruct_delta(delta_vec: Vec<secp256_k1::FE>) -> secp256_k1::FE {
        SignKeys::phase3_reconstruct_delta(&delta_vec[..])
    }

    fn secp256k1_verify_signature(sig: SignatureRecid, y: secp256_k1::GE, message: curv_kzen::BigInt) -> Result<(), multi_party_ecdsa::Error>{
        verify(&sig, &y, &message)
    }

    fn secp256k1_mul(p: secp256_k1::GE, s: secp256_k1::FE) -> secp256_k1::GE {
        p * s
    }

    fn to_big_int(message: Vec<u8>) -> BigInt {
        BigInt::from_bytes(&message)
    }

    fn secp256k1_construct_private(vss_scheme: curv_kzen::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS<secp256_k1::GE>, indices: Vec<usize>, xs: Vec<secp256_k1::FE>) -> secp256_k1::FE {
        vss_scheme.reconstruct(&indices, &xs)
    }
}
