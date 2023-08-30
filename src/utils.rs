use crate::error::RDFProofsWasmError;
use ark_std::rand::{prelude::StdRng, SeedableRng};
use oxrdf::{BlankNode, Dataset, Graph, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode, Term};
use oxttl::{NQuadsParser, NTriplesParser};
use rdf_proofs::{proof::VcWithDisclosed, vc::VerifiableCredential};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}
pub(crate) use log;

pub fn get_object_value_for_predicate(
    graph: &Graph,
    predicate: NamedNodeRef,
) -> Result<String, RDFProofsWasmError> {
    let triple = graph
        .triples_for_predicate(predicate)
        .next()
        .ok_or(RDFProofsWasmError::TripleNotExist)?;
    match triple.object {
        oxrdf::TermRef::Literal(v) => Ok(v.value().to_string()),
        _ => Err(RDFProofsWasmError::NonLiteralObject),
    }
}

pub fn get_graph_from_ntriples_str(ntriples: &str) -> Result<Graph, RDFProofsWasmError> {
    let iter = NTriplesParser::new()
        .parse_from_read(ntriples.as_bytes())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Graph::from_iter(iter))
}

pub fn get_dataset_from_nquads_str(nquads: &str) -> Result<Dataset, RDFProofsWasmError> {
    let iter = NQuadsParser::new()
        .parse_from_read(nquads.as_bytes())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Dataset::from_iter(iter))
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(rename = "secretKey")]
    pub secret_key: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeriveProofVcWithDisclosed {
    #[serde(rename = "vcDocument")]
    pub vc_document: String,
    #[serde(rename = "vcProof")]
    pub vc_proof: String,
    #[serde(rename = "disclosedDocument")]
    pub disclosed_document: String,
    #[serde(rename = "disclosedProof")]
    pub disclosed_proof: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeriveProofRequest {
    #[serde(rename = "vcWithDisclosed")]
    pub vc_with_disclosed: Vec<DeriveProofVcWithDisclosed>,
    #[serde(rename = "deanonMap")]
    pub deanon_map: HashMap<String, String>,
    pub nonce: String,
    #[serde(rename = "documentLoader")]
    pub document_loader: String,
}

impl DeriveProofRequest {
    pub fn get_vc_with_disclosed(&self) -> Vec<VcWithDisclosed> {
        self.vc_with_disclosed
            .iter()
            .map(
                |DeriveProofVcWithDisclosed {
                     vc_document,
                     vc_proof,
                     disclosed_document,
                     disclosed_proof,
                 }| {
                    VcWithDisclosed::new(
                        VerifiableCredential::new(
                            get_graph_from_ntriples_str(vc_document).unwrap(),
                            get_graph_from_ntriples_str(vc_proof).unwrap(),
                        ),
                        VerifiableCredential::new(
                            get_graph_from_ntriples_str(disclosed_document).unwrap(),
                            get_graph_from_ntriples_str(disclosed_proof).unwrap(),
                        ),
                    )
                },
            )
            .collect()
    }

    pub fn get_deanon_map(&self) -> Result<HashMap<NamedOrBlankNode, Term>, RDFProofsWasmError> {
        let re_iri = Regex::new(r"<([^>]+)>")?;
        let re_blank_node = Regex::new(r"_:(.+)")?;
        let re_simple_literal = Regex::new(r#""([^"]+)""#)?;
        let re_typed_literal = Regex::new(r#""([^"]+)"^^<([^>]+)>"#)?;
        let re_literal_with_langtag = Regex::new(r#""([^"]+)"@(.+)"#)?;

        self.deanon_map
            .iter()
            .map(|(k, v)| {
                let key: NamedOrBlankNode = if let Some(caps) = re_blank_node.captures(k) {
                    Ok(BlankNode::new_unchecked(&caps[1]).into())
                } else if let Some(caps) = re_iri.captures(k) {
                    Ok(NamedNode::new_unchecked(&caps[1]).into())
                } else {
                    Err(RDFProofsWasmError::InvalidDeanonMapFormat(k.to_string()))
                }?;
                let value: Term = if let Some(caps) = re_iri.captures(v) {
                    Ok(NamedNode::new_unchecked(&caps[1]).into())
                } else if let Some(caps) = re_simple_literal.captures(v) {
                    Ok(Literal::new_simple_literal(&caps[1]).into())
                } else if let Some(caps) = re_typed_literal.captures(v) {
                    Ok(
                        Literal::new_typed_literal(&caps[1], NamedNode::new_unchecked(&caps[2]))
                            .into(),
                    )
                } else if let Some(caps) = re_literal_with_langtag.captures(v) {
                    Ok(Literal::new_language_tagged_literal(&caps[1], &caps[2])?.into())
                } else {
                    Err(RDFProofsWasmError::InvalidDeanonMapFormat(v.to_string()))
                }?;
                Ok((key, value))
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifyProofRequest {
    pub vc_with_disclosed: Vec<(String, String, String, String)>,
    pub deanon_map: HashMap<String, String>,
    pub nonce: String,
    pub document_loader: String,
}

////////////////////////////////////////////////////////////////////////////////////
// copied from [docknetwork/crypto-wasm](https://github.com/docknetwork/crypto-wasm)
////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub error: Option<String>,
}

pub fn get_seeded_rng() -> StdRng {
    let mut buf = [0u8; 32];
    use rand::{thread_rng, RngCore as RngCoreOld};
    let mut rng = thread_rng();
    rng.fill_bytes(&mut buf);
    // getrandom is using node-js crypto module which doesn't work when building for target web. It
    // works for `wasm-pack test` with chrome in headless and normal mode
    // getrandom::getrandom(&mut buf).unwrap();
    StdRng::from_seed(buf)
}

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    {
        console_error_panic_hook::set_once();
    }
}
