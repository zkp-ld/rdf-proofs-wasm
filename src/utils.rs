use ark_std::rand::{prelude::StdRng, SeedableRng};
use oxrdf::{Graph, NamedNodeRef};
use oxttl::NTriplesParser;
use serde::{Deserialize, Serialize};

pub fn object_value_for_predicate(
    graph: &Graph,
    predicate: NamedNodeRef,
) -> Result<String, &'static str> {
    let triple = graph
        .triples_for_predicate(predicate)
        .next()
        .ok_or("triple not exist")?;
    match triple.object {
        oxrdf::TermRef::Literal(v) => Ok(v.value().to_string()),
        _ => Err("object must be literal"),
    }
}

pub fn get_graph_from_ntriples_str(ntriples: &str) -> Graph {
    Graph::from_iter(
        NTriplesParser::new()
            .parse_from_read(ntriples.as_bytes())
            .into_iter()
            .map(|x| x.unwrap()),
    )
}

////////////////////////////////////////////////////////////////////////////////////
// copied from [docknetwork/crypto-wasm](https://github.com/docknetwork/crypto-wasm)
////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub error: Option<String>,
}

impl VerifyResponse {
    pub fn validate(&self) {
        assert!(self.verified);
        assert!(self.error.is_none());
    }
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
