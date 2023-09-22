// This WASM setup script is partially based on:
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

export function initializeWasm(): Promise<void>;
export function isWasmInitialized(): boolean;
export function requireWasmInitialized(): void;

export interface KeyPair {
  readonly secretKey: string;
  readonly publicKey: string;
}

export interface VerifyResult {
  readonly verified: boolean;
  readonly error?: string;
}

export interface BlindSignRequest {
  readonly commitment: string;
  readonly pokForCommitment: string;
  readonly blinding: string;
}

export interface DeriveProofVcPair {
  readonly originalDocument: string;
  readonly originalProof: string;
  readonly disclosedDocument: string;
  readonly disclosedProof: string;
}

export interface DeriveProofRequest {
  readonly secret?: Uint8Array;
  readonly vcPairs: DeriveProofVcPair[];
  readonly deanonMap: Map<string, string>;
  readonly nonce: string;
  readonly keyGraph: string;
}

/**
 * @returns {KeyPair}
 */
export function keyGen(): KeyPair;

/**
 * @param {string} document
 * @param {string} proof
 * @param {string} keyGraph
 * @returns {string}
 */
export function sign(document: string, proof: string, keyGraph: string): string;

/**
 * @param {string} document
 * @param {string} proof
 * @param {string} keyGraph
 * @returns {VerifyResult}
 */
export function verify(
  document: string,
  proof: string,
  keyGraph: string,
): VerifyResult;

/**
 * @param {Uint8Array} secret
 * @param {string} nonce
 * @returns {BlindSignRequest}
 */
export function blindSignRequest(
  secret: Uint8Array,
  nonce: string,
): BlindSignRequest;

/**
 * @param {string} commitment
 * @param {string} pokForCommitment
 * @param {string} nonce
 * @param {string} document
 * @param {string} proof
 * @param {string} keyGraph
 * @returns {string}
 */
export function blindSign(
  commitment: string,
  pokForCommitment: string,
  nonce: string,
  document: string,
  proof: string,
  keyGraph: string,
): string;

/**
 * @param {string} document
 * @param {string} proof
 * @param {string} blinding
 * @returns {string}
 */
export function unblind(
  document: string,
  proof: string,
  blinding: string,
): string;

/**
 * @param {Uint8Array} secret
 * @param {string} document
 * @param {string} proof
 * @param {string} keyGraph
 * @returns {VerifyResult}
 */
export function blindVerify(
  secret: Uint8Array,
  document: string,
  proof: string,
  keyGraph: string,
): VerifyResult;

/**
 * @param {DeriveProofRequest} request
 * @returns {string}
 */
export function deriveProof(request: DeriveProofRequest): string;

/**
 * @param {string} vp
 * @param {string} nonce
 * @param {string} keyGraph
 * @returns {VerifyResult}
 */
export function verifyProof(
  vp: string,
  nonce: string,
  keyGraph: string,
): VerifyResult;
