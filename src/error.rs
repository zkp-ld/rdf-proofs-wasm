use rdf_proofs::error::RDFProofsError;
use std::error::Error;
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum RDFProofsWasmError {
    RDFProofsError(RDFProofsError),
}

impl From<RDFProofsWasmError> for JsValue {
    fn from(e: RDFProofsWasmError) -> Self {
        JsValue::from(&format!("{:?}", e))
    }
}

impl From<RDFProofsError> for RDFProofsWasmError {
    fn from(e: RDFProofsError) -> Self {
        Self::RDFProofsError(e)
    }
}

impl std::fmt::Display for RDFProofsWasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RDFProofsWasmError::RDFProofsError(_) => write!(f, "rdf-proofs error"),
        }
    }
}

impl Error for RDFProofsWasmError {}
