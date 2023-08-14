import init, { deriveProof, sign, verify } from "./pkg/rdf_proofs_wasm.js";

init().then(() => {
  const unsecuredDocument = `
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
_:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
_:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
  const proofConfigNtriples = `
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;
  const documentLoader = `
# issuer0
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uekl-7abY7R84yTJEJ6JRqYohXxPZPDoTinJ7XCcBkmk" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "ukiiQxfsSfV0E2QyBlnHTK2MThnd7_-Fyf6u76BUd24uxoDF4UjnXtxUo8b82iuPZBOa8BXd1NpE20x3Rfde9udcd8P8nPVLr80Xh6WLgI9SYR6piNzbHhEVIfgd_Vo9P" .
# issuer1
<did:example:issuer1> <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .
<did:example:issuer1#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer1> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uQkpZn0SW42c2tlYa0IIFXyabAYHbwc0z3l_GvXQbWSg" .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "usFM3CcvBMl_Dg5ixhQkHKGdqzY3GU9Uck6lj2i8vpbzLFOiZnjDNOpsItrkbNf2iCku-SZu5kO3nbLis-fuRhz_QwFcKw9IBpbPRPwXNQTX3zzcFsoNzs_wo8tkLQlcS" .
# issuer2
<did:example:issuer2> <https://w3id.org/security#verificationMethod> <did:example:issuer2#bls12_381-g2-pub001> .
<did:example:issuer2#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer2> .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "u4nmBsiSwvHj7i_gBu1L6Cug0OXXhVPF6NWLfkQbCZiU" .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "uo_yMZWlZwQzLqEe6hEsORbsV5cSHQEQHNI0EOe_eUJdHsgCRxtpWMcxxcdshH5pAAUxt_ni6_cQCud3CdMcjAUN8yOvzhuzeIW_H-Dyncdrc3w0f2WxdH3oRcnvPTwrb" .
# issuer3
<did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
<did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uH1yGFG6C1pJd_N45wkOPrSNdvILdLm0c_0AXXRDGZy8" .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "uidSE_Urr5MFE4SoqV3TZTBHPHM-tkpdRhBPrYeIbsudglVV_cddyEstHJOmSkfPOFsvEuA9qtWjFNpBebVSS4DPxBfNNWESSCz_vrnH62hbfpWdJSFR8YbqjborvpgM6" .
`;
  const signature = sign(unsecuredDocument, proofConfigNtriples, documentLoader);
  console.log(`signature: ${signature}`);

  const signedProof = `
  _:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
  _:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
  _:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
  _:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
  _:6b92db <https://w3id.org/security#proofValue> "${signature}"^^<https://w3id.org/security#multibase> .
  `;
  console.log(`signedProof: ${signedProof}`);

  //////////////////////////////////////////
  // verify  
  //////////////////////////////////////////
  const verified = verify(unsecuredDocument, signedProof, documentLoader);
  console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

  //////////////////////////////////////////
  // deriveProof
  //////////////////////////////////////////
  const vc_ntriples_1 = `
  <did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
  <did:example:john> <http://schema.org/name> "John Smith" .
  <did:example:john> <http://example.org/vocab/isPatientOf> _:a91b3e .
  _:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
  _:a91b3e <http://example.org/vocab/lotNumber> "0000001" .
  _:a91b3e <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
  _:a91b3e <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
  <http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
  <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
  <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
  <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  <http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  `;
  const vc_proof_ntriples_1 = `
  _:6b92db <https://w3id.org/security#proofValue> "ugZveToWB9bUAm3RDFWeORovPDYdIgNWbsquhn334R78TCG86fad_3JiA6yh_f-bsnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
  _:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
  _:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
  _:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
  _:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
  `;
  const vc_ntriples_2 = `
  <http://example.org/vaccine/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
  <http://example.org/vaccine/a> <http://schema.org/name> "AwesomeVaccine" .
  <http://example.org/vaccine/a> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
  <http://example.org/vaccine/a> <http://schema.org/status> "active" .
  <http://example.org/vicred/a> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
  <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/a> .
  <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
  <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  <http://example.org/vicred/a> <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  `;
  const vc_proof_ntriples_2 = `
  _:wTnTxH <https://w3id.org/security#proofValue> "upqbT4ZPXjIRFKEQt5k-Bs5g_KG50zREjSMFH0wL5wkDAs7Ci2Qg58_EJLDffc2M0nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
  _:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
  _:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
  _:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
  _:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
  `;
  const disclosed_vc_ntriples_1 = `
  _:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
  _:e0 <http://example.org/vocab/isPatientOf> _:a91b3e .
  _:a91b3e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
  _:a91b3e <http://example.org/vocab/vaccine> _:e1 .
  _:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
  _:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
  _:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
  _:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  `;
  const disclosed_vc_proof_ntriples_1 = `
  _:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
  _:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
  _:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
  _:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
  `;
  const disclosed_vc_ntriples_2 = `
  _:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
  _:e1 <http://schema.org/status> "active" .
  _:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
  _:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
  _:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
  _:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  `;
  const disclosed_vc_proof_ntriples_2 = `
  _:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
  _:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
  _:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
  _:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
  _:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
  `;
  const deanonMap = {
    "e0": "did:example:john",
    "e1": "http://example.org/vaccine/a",
    "e2": "http://example.org/vcred/00",
    "e3": "http://example.org/vicred/a"
  };

  const verified1 = verify(vc_ntriples_1, vc_proof_ntriples_1, documentLoader);
  console.log(`verified for vc1: ${JSON.stringify(verified1, null, 2)}`);
  const verified2 = verify(vc_ntriples_2, vc_proof_ntriples_2, documentLoader);
  console.log(`verified for vc2: ${JSON.stringify(verified2, null, 2)}`);

  const nonce = "abcde";
  const deriveProofRequest = {
    vc_with_disclosed: [
      [vc_ntriples_1, vc_proof_ntriples_1, disclosed_vc_ntriples_1, disclosed_vc_proof_ntriples_1],
      [vc_ntriples_2, vc_proof_ntriples_2, disclosed_vc_ntriples_2, disclosed_vc_proof_ntriples_2]
    ],
    deanon_map: deanonMap,
    nonce: nonce,
    document_loader: documentLoader,
  }
  console.log(`deriveProofRequest: ${JSON.stringify(deriveProofRequest, null, 2)}`);
  const deriveProofResponse = deriveProof(deriveProofRequest);
  console.log(`deriveProofResponse: ${deriveProofResponse}`);
});
