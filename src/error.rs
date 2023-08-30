use oxrdf::LanguageTagParseError;
use oxttl::ParseError;
use rdf_proofs::error::RDFProofsError;
use std::error::Error;
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum RDFProofsWasmError {
    ParseError(ParseError),
    RDFProofsError(RDFProofsError),
    TripleNotExist,
    NonLiteralObject,
    InvalidDeanonMapFormat(String),
}

impl From<RDFProofsWasmError> for JsValue {
    fn from(e: RDFProofsWasmError) -> Self {
        JsValue::from(&format!("{:?}", e))
    }
}

impl From<ParseError> for RDFProofsWasmError {
    fn from(e: ParseError) -> Self {
        Self::ParseError(e)
    }
}

impl From<RDFProofsError> for RDFProofsWasmError {
    fn from(e: RDFProofsError) -> Self {
        Self::RDFProofsError(e)
    }
}

impl From<LanguageTagParseError> for RDFProofsWasmError {
    fn from(e: LanguageTagParseError) -> Self {
        Self::InvalidDeanonMapFormat(e.to_string())
    }
}

impl From<regex::Error> for RDFProofsWasmError {
    fn from(e: regex::Error) -> Self {
        Self::InvalidDeanonMapFormat(e.to_string())
    }
}

impl std::fmt::Display for RDFProofsWasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RDFProofsWasmError::ParseError(_) => write!(f, "parse error"),
            RDFProofsWasmError::RDFProofsError(_) => write!(f, "rdf-proofs error"),
            RDFProofsWasmError::TripleNotExist => write!(f, "triple not exist error"),
            RDFProofsWasmError::NonLiteralObject => write!(f, "non literal object error"),
            RDFProofsWasmError::InvalidDeanonMapFormat(e) => {
                write!(f, "given deanon map has invalid format: {}", e)
            }
        }
    }
}

impl Error for RDFProofsWasmError {}
