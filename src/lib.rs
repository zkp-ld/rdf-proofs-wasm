mod utils;

use crate::utils::{get_graph_from_ntriples_str, get_seeded_rng, object_value_for_predicate};
use rdf_proofs::{
    context::PROOF_VALUE,
    loader::DocumentLoader,
    proof::derive_proof,
    signature::{sign, verify},
    vc::VerifiableCredential,
};
use utils::{log, set_panic_hook, DeriveProofRequest, VerifyResponse};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = sign)]
pub fn sign_caller(document: &str, proof: &str, document_loader: &str) -> Result<String, JsValue> {
    set_panic_hook();

    let document_loader: DocumentLoader =
        get_graph_from_ntriples_str(document_loader).unwrap().into();
    let unsecured_document = get_graph_from_ntriples_str(document).unwrap();
    let proof_config = get_graph_from_ntriples_str(proof).unwrap();
    let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
    let mut rng = get_seeded_rng();
    match sign(&mut rng, &mut vc, &document_loader) {
        Ok(()) => object_value_for_predicate(&vc.proof, PROOF_VALUE)
            .map_err(|e| JsValue::from(&format!("{:?}", e))),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = verify)]
pub fn verify_caller(
    document: &str,
    proof: &str,
    document_loader: &str,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let document_loader: DocumentLoader =
        get_graph_from_ntriples_str(document_loader).unwrap().into();
    let unsecured_document = get_graph_from_ntriples_str(document).unwrap();
    let proof_config = get_graph_from_ntriples_str(proof).unwrap();
    let mut vc = VerifiableCredential::new(unsecured_document, proof_config);
    log(format!("vc to be verified: {:#?}", vc.document));
    log(format!("vc to be verified: {:#?}", vc.proof));

    match verify(&mut vc, &document_loader).map_err(|e| JsValue::from(&format!("{:?}", e))) {
        Ok(_) => serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        }),
        Err(e) => serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        }),
    }
    .map_err(|e| JsValue::from(&format!("{:?}", e)))
}

#[wasm_bindgen(js_name = deriveProof)]
pub fn derive_proof_caller(request: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let request: DeriveProofRequest =
        serde_wasm_bindgen::from_value(request).map_err(|e| JsValue::from(&format!("{:?}", e)))?;
    let mut rng = get_seeded_rng();
    let vcs = request.get_vc_with_disclosed();
    let deanon_map = request.get_deanon_map();
    let nonce = &request.nonce;
    let document_loader: DocumentLoader = get_graph_from_ntriples_str(&request.document_loader)
        .unwrap()
        .into();
    let vp = derive_proof(
        &mut rng,
        &vcs,
        &deanon_map,
        Some(nonce.as_bytes()),
        &document_loader,
    )
    .map_err(|e| JsValue::from(&format!("{:?}", e)))?;
    Ok(rdf_canon::serialize(&vp))
}
