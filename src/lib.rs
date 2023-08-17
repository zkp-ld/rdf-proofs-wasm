mod error;
mod utils;

use crate::utils::{get_graph_from_ntriples_str, get_object_value_for_predicate, get_seeded_rng};
use error::RDFProofsWasmError;
use rdf_proofs::{
    context::PROOF_VALUE,
    keygen::{generate_keypair, serialize_public_key, serialize_secret_key},
    loader::DocumentLoader,
    proof::{derive_proof, verify_proof},
    signature::{sign, verify},
    vc::VerifiableCredential,
};
use utils::{
    get_dataset_from_nquads_str, set_panic_hook, DeriveProofRequest, KeyPair, VerifyResult,
};
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
pub fn sign_caller(document: &str, proof: &str, document_loader: &str) -> Result<String, JsValue> {
    set_panic_hook();

    let document_loader: DocumentLoader = get_graph_from_ntriples_str(document_loader)?.into();
    let unsecured_document = get_graph_from_ntriples_str(document)?;
    let proof_config = get_graph_from_ntriples_str(proof)?;
    let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
    let mut rng = get_seeded_rng();
    sign(&mut rng, &mut vc, &document_loader).map_err(RDFProofsWasmError::from)?;
    Ok(get_object_value_for_predicate(&vc.proof, PROOF_VALUE)?)
}

#[wasm_bindgen(js_name = verify)]
pub fn verify_caller(
    document: &str,
    proof: &str,
    document_loader: &str,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let document_loader: DocumentLoader = get_graph_from_ntriples_str(document_loader)?.into();
    let unsecured_document = get_graph_from_ntriples_str(document)?;
    let proof_config = get_graph_from_ntriples_str(proof)?;
    let vc = VerifiableCredential::new(unsecured_document, proof_config);

    match verify(&vc, &document_loader) {
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
    let vcs = request.get_vc_with_disclosed();
    let deanon_map = request.get_deanon_map();
    let nonce = &request.nonce;
    let document_loader: DocumentLoader =
        get_graph_from_ntriples_str(&request.document_loader)?.into();
    let vp = derive_proof(
        &mut rng,
        &vcs,
        &deanon_map,
        Some(nonce.as_bytes()),
        &document_loader,
    )
    .map_err(RDFProofsWasmError::from)?;
    Ok(rdf_canon::serialize(&vp))
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof_caller(
    vp: &str,
    nonce: &str,
    document_loader: &str,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let document_loader: DocumentLoader = get_graph_from_ntriples_str(document_loader)?.into();
    let vp_dataset = get_dataset_from_nquads_str(vp)?;
    let mut rng = get_seeded_rng();

    match verify_proof(
        &mut rng,
        &vp_dataset,
        Some(nonce.as_bytes()),
        &document_loader,
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
