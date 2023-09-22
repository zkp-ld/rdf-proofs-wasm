mod error;
mod utils;

use crate::utils::get_seeded_rng;
use error::RDFProofsWasmError;
use rdf_proofs::{
    blind_sign_request_string, blind_sign_string, blind_verify_string, derive_proof_string,
    key_gen::{generate_keypair, serialize_public_key, serialize_secret_key},
    sign_string, unblind_string, verify_proof_string, verify_string, VcPairString,
};
use utils::{set_panic_hook, DeriveProofRequest, KeyPair, VerifyResult};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = keyGen)]
pub fn key_gen_caller() -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let keypair = generate_keypair(&mut rng).map_err(RDFProofsWasmError::from)?;
    let secret_key = serialize_secret_key(&keypair.secret_key).map_err(RDFProofsWasmError::from)?;
    let public_key = serialize_public_key(&keypair.public_key).map_err(RDFProofsWasmError::from)?;
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

#[wasm_bindgen(js_name = blindSignRequest)]
pub fn blind_sign_request_caller(secret: &[u8], nonce: &str) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let req_and_blinding = blind_sign_request_string(&mut rng, secret, Some(nonce))
        .map_err(RDFProofsWasmError::from)?;
    Ok(serde_wasm_bindgen::to_value(&req_and_blinding)?)
}

#[wasm_bindgen(js_name = blindSign)]
pub fn blind_sign_caller(
    request: &str,
    nonce: &str,
    document: &str,
    proof: &str,
    key_graph: &str,
) -> Result<String, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();
    let proof_value = blind_sign_string(&mut rng, request, Some(nonce), document, proof, key_graph)
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
pub fn derive_proof_caller(request: JsValue) -> Result<String, JsValue> {
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

    // convert `Option<Vec<u8>>` to `Option<&[u8]>`
    let secret = request.secret.as_ref().map(AsRef::as_ref);

    let vp = derive_proof_string(
        &mut rng,
        secret,
        &vc_pairs,
        &request.deanon_map,
        Some(&request.nonce),
        &request.key_graph,
    )
    .map_err(RDFProofsWasmError::from)?;
    Ok(vp)
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof_caller(vp: &str, nonce: &str, key_graph: &str) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let mut rng = get_seeded_rng();

    match verify_proof_string(&mut rng, vp, Some(nonce), key_graph) {
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
