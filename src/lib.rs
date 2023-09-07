mod error;
mod utils;

use crate::utils::get_seeded_rng;
use error::RDFProofsWasmError;
use rdf_proofs::{
    derive_proof_string,
    key_gen::{generate_keypair, serialize_public_key, serialize_secret_key},
    sign_string, verify_proof_string, verify_string, VcPairString,
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
    let vp = derive_proof_string(
        &mut rng,
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
