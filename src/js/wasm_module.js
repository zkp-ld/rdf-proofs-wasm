"use strict";

// This WASM setup script is based on:
// [docknetwork/crypto-wasm](https://github.com/docknetwork/crypto-wasm) and
// [mattrglobal/bbs-signatures](https://github.com/mattrglobal/bbs-signatures)

/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// TODO should be able to remove this duplicate definition syntax by using ESM over index.web.js
// in future

const {
  wasm, isWasmInitialized, requireWasmInitialized, initializeWasm
} = require('./init_wasm');

module.exports = {
  isWasmInitialized, requireWasmInitialized, initializeWasm,
};

module.exports.keyGen = () => {
  requireWasmInitialized();

  return wasm.keyGen();
}

module.exports.sign = (document, proof, keyGraph) => {
  requireWasmInitialized();

  return wasm.sign(document, proof, keyGraph);
}

module.exports.verify = (document, proof, keyGraph) => {
  requireWasmInitialized();

  return wasm.verify(document, proof, keyGraph);
}

module.exports.blindSignRequest = (secret, nonce) => {
  requireWasmInitialized();

  return wasm.blindSignRequest(secret, nonce);
}

module.exports.blindSign = (request, nonce, document, proof, keyGraph) => {
  requireWasmInitialized();

  return wasm.blindSign(request, nonce, document, proof, keyGraph);
}

module.exports.unblind = (document, proof, blinding) => {
  requireWasmInitialized();

  return wasm.unblind(document, proof, blinding);
}

module.exports.blindVerify = (secret, document, proof, keyGraph) => {
  requireWasmInitialized();

  return wasm.blindVerify(secret, document, proof, keyGraph);
}

module.exports.deriveProof = (request) => {
  requireWasmInitialized();

  return wasm.deriveProof(request);
}

module.exports.verifyProof = (vp, nonce, keyGraph) => {
  requireWasmInitialized();

  return wasm.verifyProof(vp, nonce, keyGraph);
}
