mod error;
mod utils;

use crate::utils::get_seeded_rng;
use error::RDFProofsWasmError;
use rdf_proofs::{
    ark_to_base64url, blind_sign_string, blind_verify_string, derive_proof_string,
    key_gen::generate_keypair, request_blind_sign_string, sign_string, unblind_string,
    verify_blind_sign_request_string, verify_proof_string, verify_string, VcPairString,
};
use utils::{set_panic_hook, DeriveProofRequest, KeyPair, VerifyResult};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = keyGen)]
pub fn key_gen_caller() -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let keypair = generate_keypair(&mut rng).map_err(RDFProofsWasmError::from)?;
    let secret_key = ark_to_base64url(&keypair.secret_key).map_err(RDFProofsWasmError::from)?;
    let public_key = ark_to_base64url(&keypair.public_key).map_err(RDFProofsWasmError::from)?;
    Ok(serde_wasm_bindgen::to_value(&KeyPair {
        secret_key,
        public_key,
    })?)
}

#[wasm_bindgen(js_name = sign)]
pub fn sign_caller(document: &str, proof: &str, key_graph: &str) -> Result<String, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let proof_value =
        sign_string(&mut rng, document, proof, key_graph).map_err(RDFProofsWasmError::from)?;
    Ok(proof_value)
}

#[wasm_bindgen(js_name = verify)]
pub fn verify_caller(document: &str, proof: &str, key_graph: &str) -> Result<JsValue, JsValue> {
    set_panic_hook();

    match verify_string(document, proof, key_graph) {
        Ok(()) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: true,
            error: None,
        })?),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: false,
            error: Some(format!("{:?}", e)),
        })?),
    }
}

#[wasm_bindgen(js_name = requestBlindSign)]
pub fn request_blind_sign_caller(
    secret: &[u8],
    challenge: Option<String>,
    skip_pok: Option<bool>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let req_and_blinding =
        request_blind_sign_string(&mut rng, secret, challenge.as_deref(), skip_pok)
            .map_err(RDFProofsWasmError::from)?;
    Ok(serde_wasm_bindgen::to_value(&req_and_blinding)?)
}

#[wasm_bindgen(js_name = verifyBlindSignRequest)]
pub fn verify_blind_sign_request_caller(
    commitment: &str,
    pok_for_commitment: &str,
    challenge: Option<String>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    match verify_blind_sign_request_string(
        &mut rng,
        commitment,
        pok_for_commitment,
        challenge.as_deref(),
    ) {
        Ok(()) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: true,
            error: None,
        })?),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: false,
            error: Some(format!("{:?}", e)),
        })?),
    }
}

#[wasm_bindgen(js_name = blindSign)]
pub fn blind_sign_caller(
    commitment: &str,
    document: &str,
    proof_options: &str,
    key_graph: &str,
) -> Result<String, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let proof_value = blind_sign_string(&mut rng, commitment, document, proof_options, key_graph)
        .map_err(RDFProofsWasmError::from)?;
    Ok(proof_value)
}

#[wasm_bindgen(js_name = unblind)]
pub fn unblind(document: &str, proof: &str, blinding: &str) -> Result<String, JsValue> {
    set_panic_hook();

    let proof_value =
        unblind_string(document, proof, blinding).map_err(RDFProofsWasmError::from)?;
    Ok(proof_value)
}

#[wasm_bindgen(js_name = blindVerify)]
pub fn blind_verify_caller(
    secret: &[u8],
    document: &str,
    proof: &str,
    key_graph: &str,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    match blind_verify_string(secret, document, proof, key_graph) {
        Ok(()) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: true,
            error: None,
        })?),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: false,
            error: Some(format!("{:?}", e)),
        })?),
    }
}

#[wasm_bindgen(js_name = deriveProof)]
pub fn derive_proof_caller(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let request: DeriveProofRequest = serde_wasm_bindgen::from_value(request)?;
    let mut rng = get_seeded_rng();
    let vc_pairs = request
        .vc_pairs
        .into_iter()
        .map(|vc_pair| {
            VcPairString::new(
                &vc_pair.original_document,
                &vc_pair.original_proof,
                &vc_pair.disclosed_document,
                &vc_pair.disclosed_proof,
            )
        })
        .collect();

    let vp = derive_proof_string(
        &mut rng,
        &vc_pairs,
        &request.deanon_map,
        &request.key_graph,
        request.challenge.as_deref(),
        request.domain.as_deref(),
        request.secret.as_deref(),
        request.blind_sign_request,
    )
    .map_err(RDFProofsWasmError::from)?;
    Ok(serde_wasm_bindgen::to_value(&vp)?)
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof_caller(
    vp: &str,
    key_graph: &str,
    challenge: Option<String>,
    domain: Option<String>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();

    match verify_proof_string(
        &mut rng,
        vp,
        key_graph,
        challenge.as_deref(),
        domain.as_deref(),
    ) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: true,
            error: None,
        })?),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResult {
            verified: false,
            error: Some(format!("{:?}", e)),
        })?),
    }
}
