"use strict";

// This WASM setup script is based on:
// [docknetwork/crypto-wasm](https://github.com/docknetwork/crypto-wasm) and
// [mattrglobal/bbs-signatures](https://github.com/mattrglobal/bbs-signatures)

/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require("fs");
const buffer = fs.readFileSync("./lib/rdf_proofs_wasm_bg.wasm");

fs.writeFileSync(
  "./lib/rdf_proofs_wasm_bs64.js",
  `
module.exports = Buffer.from('${buffer.toString("base64")}', 'base64');
`
);
