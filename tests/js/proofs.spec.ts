import {
  DeriveProofRequest,
  deriveProof,
  initializeWasm,
  sign,
  verify,
  verifyProof,
} from '../../lib';
import { DeriveProofVcPair } from '../../src/js';

const keyGraph = `
# issuer0
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uekl-7abY7R84yTJEJ6JRqYohXxPZPDoTinJ7XCcBkmk" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "ukiiQxfsSfV0E2QyBlnHTK2MThnd7_-Fyf6u76BUd24uxoDF4UjnXtxUo8b82iuPZBOa8BXd1NpE20x3Rfde9udcd8P8nPVLr80Xh6WLgI9SYR6piNzbHhEVIfgd_Vo9P" .
# issuer3
<did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
<did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "uH1yGFG6C1pJd_N45wkOPrSNdvILdLm0c_0AXXRDGZy8" .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "uidSE_Urr5MFE4SoqV3TZTBHPHM-tkpdRhBPrYeIbsudglVV_cddyEstHJOmSkfPOFsvEuA9qtWjFNpBebVSS4DPxBfNNWESSCz_vrnH62hbfpWdJSFR8YbqjborvpgM6" .    
`;

describe('Proofs', () => {
  test('sign', async () => {
    await initializeWasm();

    const doc = `
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
<did:example:john> <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/lotNumber> "0000001" .
_:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b1 <http://schema.org/name> "ABC inc." .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
    const proof = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;

    const signature = sign(doc, proof, keyGraph);
    console.log(`signature: ${signature}`);

    expect(signature).toBeDefined();
  });

  test('verify', async () => {
    await initializeWasm();

    const doc = `
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
<did:example:john> <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/lotNumber> "0000001" .
_:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b1 <http://schema.org/name> "ABC inc." .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
    const proof = `
_:b0 <https://w3id.org/security#proofValue> "utEnCefxSJlHuHFWGuCEqapeOkbNUMcUZfixkTP-eelRRXBCUpSl8wNNxHQqDcVgDnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;

    const verified = verify(doc, proof, keyGraph);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });

  const doc1 = `
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
<did:example:john> <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/lotNumber> "0000001" .
_:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b1 <http://schema.org/name> "ABC inc." .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
  const proof1 = `
_:b0 <https://w3id.org/security#proofValue> "utEnCefxSJlHuHFWGuCEqapeOkbNUMcUZfixkTP-eelRRXBCUpSl8wNNxHQqDcVgDnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;
  const doc2 = `
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
  const proof2 = `
_:b0 <https://w3id.org/security#proofValue> "usjQI4FuaD8udL2e5Rhvf4J4L0IOjmXT7Q3E40FXnIG-GQ6GMJkUuLv5tU1gJjW42nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
`;
  const disclosedDoc1 = `
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://example.org/vocab/isPatientOf> _:b0 .
_:e0 <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/vaccine> _:e1 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
  const disclosedProof1 = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;
  const disclosedDoc2 = `
_:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
_:e1 <http://schema.org/status> "active" .
_:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
_:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
_:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
  const disclosedProof2 = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
`;
  const disclosedDoc1WithHiddenLiterals = `
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://example.org/vocab/isPatientOf> _:b0 .
_:e0 <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/vaccinationDate> _:vdate .
_:b0 <http://example.org/vocab/vaccine> _:e1 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;

  test('deriveProof', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const nonce = 'abcde';

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: proof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedProof1,
    };
    const vcPair2: DeriveProofVcPair = {
      originalDocument: doc2,
      originalProof: proof2,
      disclosedDocument: disclosedDoc2,
      disclosedProof: disclosedProof2,
    };

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1, vcPair2],
      deanonMap,
      nonce,
      keyGraph,
    };
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();
  });

  test('deriveProof with invalid deanonMap', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const nonce = 'abcde';

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: proof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedProof1,
    };

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1],
      deanonMap,
      nonce,
      keyGraph,
    };

    expect(() => {
      deriveProof(req);
    }).toThrow('InvalidDeanonMapFormat("e0")');
  });

  test('deriveProof with hidden literals', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
      [
        '_:vdate',
        '"2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime>',
      ],
    ]);
    const nonce = 'abcde';

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: proof1,
      disclosedDocument: disclosedDoc1WithHiddenLiterals,
      disclosedProof: disclosedProof1,
    };
    const vcPair2: DeriveProofVcPair = {
      originalDocument: doc2,
      originalProof: proof2,
      disclosedDocument: disclosedDoc2,
      disclosedProof: disclosedProof2,
    };

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1, vcPair2],
      deanonMap,
      nonce,
      keyGraph,
    };
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();
  });

  test('verifyProof', async () => {
    await initializeWasm();

    const vp = `
_:c14n10 <http://example.org/vocab/vaccine> _:c14n5 _:c14n6 .
_:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n6 .
_:c14n12 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n6 .
_:c14n12 <http://schema.org/worksFor> _:c14n8 _:c14n6 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n6 .
_:c14n13 <http://purl.org/dc/terms/created> "2023-08-30T11:49:24.405Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n1 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n1 .
_:c14n13 <https://w3id.org/security#challenge> "abcde" _:c14n1 .
_:c14n13 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n1 .
_:c14n13 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n1 .
_:c14n13 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJ2gIAAAAAAAAAAIAhi1TuFxmvzA_kdD5gdNMmzimzh2y1l6qAClgnxmOGS33FibuZXHDG8YJULlHNaYFQJy5EgiQB62iB7fObqn3A3cDLIikk9f9BtnPal0xiCjz8BnTK4fYj6K-D8pWGDKhNR7r6cbj3DZjlBl192768dOzfCv-OYNYE9xlIJ6cyAHZZ8_rx0_zashEJH6PTO4bP1w7dnb0h0UgKwCMtrvYIf59Chd9KHEoiuriQq0S9VmaLdlAkhTdIPMRqSFrcQQIAAAAAAAAAzlSYUyif3e3AdHGc2SS1aDK_BT9809gtIeEKy9i7qifsn2wP2_e-P6mU1_xHLDXdnHp-kX2Agyi1SsVKr6CZCJMaCl5MueLD9At3jlguFj8gQoXPPo4a1i3LDOi47WvfjO7Y1tTjh2RGKnbZaUm_GCUAAAAAAAAAfOJc2HSm71ZcABpUEK8D_PugfcbOhh5X2gZwvdXQ4HK1Kl5fJCOWOaVIxJ4IRU4iIm7jLNmkBzHws_nxMXttR9pR6B3dl8xlEEXoEdf6ywIPWXvu4Ua0mA9_7MX1xg5WlQZ0X0bHwCFlyXjaLYZJAYfe1e-MnBucYi8G4CxF4BRiCuTyKnpeb0GH7F8qUk9-AO-fgKfF2d-FsSTbxFWYJFElp1K3MhbxWLKRHee9E_UlwvA8EMsxC6Y0Oj8Sei8Ami_m95mv8XXqYY3bT6XX9HliTzEpVvZb6LDZVvPS6yLaUegd3ZfMZRBF6BHX-ssCD1l77uFGtJgPf-zF9cYOVuscrMt-sinykGfPdWj9MBlAWhoGIITW895F7k7P1g032lHoHd2XzGUQRegR1_rLAg9Ze-7hRrSYD3_sxfXGDlaefodrghOcy-YMF8yzgpLnQKSSHV9lnec7mMj57Z5RMJ5-h2uCE5zL5gwXzLOCkudApJIdX2Wd5zuYyPntnlEw2lHoHd2XzGUQRegR1_rLAg9Ze-7hRrSYD3_sxfXGDlaefodrghOcy-YMF8yzgpLnQKSSHV9lnec7mMj57Z5RMJ5-h2uCE5zL5gwXzLOCkudApJIdX2Wd5zuYyPntnlEwnn6Ha4ITnMvmDBfMs4KS50Ckkh1fZZ3nO5jI-e2eUTD0ZKofE2pv7bSFHRf6BiiloHDZ3j5Q1GJ0kCu7YuBZQ41l-9H7G-XdaaVGqDbPTR1jgf2vzshL-Y4HIRoRnxZsFvo3Ot4UVcsb2urSoifthJD_2RE0MevDS1Bzi-iEaEvrHKzLfrIp8pBnz3Vo_TAZQFoaBiCE1vPeRe5Oz9YNNyiiAUhiaYksBK1MUtU5SElxQumrTTpVP6Wt20XE8zAem_gj3znGhdHs64JlWON9dXxPiTOXarJ9hnczcqdrSGexxKpaO98MSTIn1xNdpb9Xeq4p4gmMsFowpZBcZRemVr1IMOn1adO7LPHVNrPfIGlrTR_yF9GIICNhIKhKRMYAVhjBsohiEzok88DuLtnx4BKMMKbXyfUqOBiPDLWXzypHdO4LwcuzJ-_37PORwRGN6Dd3y--G6X893pLZEjHpV5UGdF9Gx8AhZcl42i2GSQGH3tXvjJwbnGIvBuAsReAUm0D0WBzgBueCsv-Rjd4I08hNpfgYVQ_2T1yuDCXyJSmlVHk5rA5kxfzdI1TNxxP12N1DFajC-w3Ly5unNFTqB1_Pt01BFjsd0xArF0K4e8vQ218C6vyblX_xgOYnuF1DNIYd4kk1aVTOmGRCANHuyEOqAzbvnsZWMWSHkhm4NmKVBnRfRsfAIWXJeNothkkBh97V74ycG5xiLwbgLEXgFNqu_RIaN9RF1Qq35UYl4h2VgzmHlDRHSga9juZ5GV8K2q79Eho31EXVCrflRiXiHZWDOYeUNEdKBr2O5nkZXwrarv0SGjfURdUKt-VGJeIdlYM5h5Q0R0oGvY7meRlfCtqu_RIaN9RF1Qq35UYl4h2VgzmHlDRHSga9juZ5GV8K2q79Eho31EXVCrflRiXiHZWDOYeUNEdKBr2O5nkZXwoAhClyUGZnZKN3Dcg1jwp8Wb78Szp3X19pz0zB1yLInk0xZvNrM8Lhbn7Ua4LiPehLjt_cUnYPgTXP2Ak_F5D5ANz28oLnXVpmwgpVWWpWvrKl6RFMZAbzBpH6fd1nZKARlRXxOKU4X2AWAGern-8RCxFkrsLS2poTsO6CFH1-rEThHCX_D3v1VPt478ziwOQ8oAhGBr6QzmUBVXEuHs6kLx-p3ZcVZYw_FNMdZgYjwosmvJx7Vo_ZJ-u5-c_j3YdoAgAAAAAAAAAUShdapBVeXbEKZP058g1BNCI3IpxrwQb92QawhCAlb8j2ISnu53EDYi7voWOl99GwvHqkeGnSzLekaC3qCHhqsXDALiHxk_xjHjNa2mDBWTs0myKPHBX5mqi74DHi0Bi26RJ4nZc9aLXAIGAXJ4sCFQAAAAAAAAAdVJ_o7kPPkC_JCPelsXcAiLYQYsApOWdXMkS9rMgragRsDNoydC_-X_tT5TOlAPTsyfPIhqVuKkzvqJvEx3o2mdPH23P-abOCw4hGIvSfOXwJyXRNXiWJLLb2AJqqSBdh1zKFMHjflEmrzsLvK5Jjnigr9oT7jM-ovCw2bz6lQKy7FiNzlPpitH38bfOKQPmkwHqsbCwJFScGRuFmjPoCfNpM5VZDCKncXF9QiL1Rh0COxFSE4CUFOFzU3Dj-VlBv8S6KObZ6OAEEZPQqkbfZ2j5R9MidKvqzzgx5DkelX8VNTVMbzSHeChdUhN-CegaXxgBgLcH7wii7znYhVWQlm0D0WBzgBueCsv-Rjd4I08hNpfgYVQ_2T1yuDCXyJSmbQPRYHOAG54Ky_5GN3gjTyE2l-BhVD_ZPXK4MJfIlKa-gXXC7wMkTDN1r6PhUNXdWzB1pW6Zi0eY3yUp2t1Rzr6BdcLvAyRMM3Wvo-FQ1d1bMHWlbpmLR5jfJSna3VHObQPRYHOAG54Ky_5GN3gjTyE2l-BhVD_ZPXK4MJfIlKa-gXXC7wMkTDN1r6PhUNXdWzB1pW6Zi0eY3yUp2t1Rzr6BdcLvAyRMM3Wvo-FQ1d1bMHWlbpmLR5jfJSna3VHOvoF1wu8DJEwzda-j4VDV3VswdaVumYtHmN8lKdrdUc4hMc_rhpyfqKO7KkjxWGM5ae5NcCYBV-KmVTlecd3BKiExz-uGnJ-oo7sqSPFYYzlp7k1wJgFX4qZVOV5x3cEqITHP64acn6ijuypI8VhjOWnuTXAmAVfiplU5XnHdwSohMc_rhpyfqKO7KkjxWGM5ae5NcCYBV-KmVTlecd3BKiExz-uGnJ-oo7sqSPFYYzlp7k1wJgFX4qZVOV5x3cEoBBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGLDQ8AAgMEBQYHCAphMhBhM4UAAQIDBGE0BaRhMYcCAwQFBgcIYTIJYTOFAAECAwRhNAU"^^<https://w3id.org/security#multibase> _:c14n1 .
_:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
_:c14n14 <https://w3id.org/security#proof> _:c14n11 _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n12 _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n6 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
_:c14n3 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n3 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
_:c14n3 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n3 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
_:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n4 <https://w3id.org/security#proof> _:c14n1 .
_:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
_:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
_:c14n5 <http://schema.org/status> "active" _:c14n7 .
_:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
_:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n6 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
_:c14n9 <https://w3id.org/security#proof> _:c14n0 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .    
`;
    const nonce = 'abcde';

    const verified = verifyProof(vp, nonce, keyGraph);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });
});
