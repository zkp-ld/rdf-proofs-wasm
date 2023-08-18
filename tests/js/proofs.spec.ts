import {
  DeriveProofRequest,
  deriveProof,
  initializeWasm,
  sign,
  verify,
  verifyProof,
} from '../../lib';
import { DeriveProofVcWithDisclosed } from '../../src/js';

const documentLoader = `
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

    const signature = sign(doc, proof, documentLoader);
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

    const verified = verify(doc, proof, documentLoader);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof', async () => {
    await initializeWasm();

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
    const deanonMap = new Map([
      ['e0', 'did:example:john'],
      ['e1', 'http://example.org/vaccine/a'],
      ['e2', 'http://example.org/vcred/00'],
      ['e3', 'http://example.org/vicred/a'],
    ]);
    const nonce = 'abcde';

    const vcWithDisclosed1: DeriveProofVcWithDisclosed = {
      vcDocument: doc1,
      vcProof: proof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedProof1,
    };
    const vcWithDisclosed2: DeriveProofVcWithDisclosed = {
      vcDocument: doc2,
      vcProof: proof2,
      disclosedDocument: disclosedDoc2,
      disclosedProof: disclosedProof2,
    };

    const req: DeriveProofRequest = {
      vcWithDisclosed: [vcWithDisclosed1, vcWithDisclosed2],
      deanonMap,
      nonce,
      documentLoader,
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
_:c14n12 <http://purl.org/dc/terms/created> "2023-08-18T08:13:14.264012316Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n12 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n0 .
_:c14n12 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n12 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJ2gIAAAAAAAAAAKzAMv_PeFt9Aa3flTPd1SLsP6q0CsKszGN6L-Pn9cUXWJEm9SnYMjLcbUBKEvsnyqrOUXkOMid0Rxhxt09lQ0EeKMYQ9B15WyRyrFNjLdXct0nFiUno1Gl7cvmLR2PsvbjgF5qGnIHo1dcEmt5DUstWhVttwiYEPhLd8PIXYuAX9_D4KdIZQJn-SO3ESmcKroyImV-fCl9jT9VwRdPGrwz8_TGHsOGiUj2yX280cQFxsWhvcWfqDsCJEpyY-DdGvAIAAAAAAAAA1okw0jGUiqR5jcPv8qbZGZn91nEO7IOWf8ouTcm9igyVx-camoRtWmAW9H6Bg6oAIiWiH0E7-5wKKxdjzUKBBYC3nZqbumW9xCTYSA_QN1D0eYEi5TpYgtVluzGhQLDYQKiw6maZ3Egx4EMKe1tB_CUAAAAAAAAAV_eCYffh0hlP8RSzN1IG0_WJBfS139zIpDvTNjclfigh0FT26KXHvnB-mj9L8XlLAWRMJFHLDdTRmoNEXlR0HRY9MOO6d30_c0Dcp35_TeGBwto3UOGdcXdzF9zwQC80JxlAbuEueM7aXR0gRDB99Oaq2lA2couyRFOK3lEb0i0uBHsnn-wTgHu2C1Gwps1cRSjoUb_bXcZM8sxkmmSHKA1Db2JYtsTZ11LCrlMlFMlAScKjyPsWqSFVh10W4HRjr2CsQzPFDQ7mirLoylgnGsNjIJjqaCr65szmYAMwxCcWPTDjund9P3NA3Kd-f03hgcLaN1DhnXF3cxfc8EAvNLB5CGSzry6PW0bv2TyZxlar597HOAOpD_y3l5aOG3IiFj0w47p3fT9zQNynfn9N4YHC2jdQ4Z1xd3MX3PBALzSfHaa2rZwGHE4fuxCh4RGx2Lp3lMl37lCxtbOw-IYdS58dpratnAYcTh-7EKHhEbHYuneUyXfuULG1s7D4hh1LFj0w47p3fT9zQNynfn9N4YHC2jdQ4Z1xd3MX3PBALzSfHaa2rZwGHE4fuxCh4RGx2Lp3lMl37lCxtbOw-IYdS58dpratnAYcTh-7EKHhEbHYuneUyXfuULG1s7D4hh1Lnx2mtq2cBhxOH7sQoeERsdi6d5TJd-5QsbWzsPiGHUvjJLqIP5lt6l47j7STuW4Crx8t4CIWYX1bwGwBwq4Wb1JfQjQkteZdftP1ESWwHYxb5MtOKQDYqG2tVsL67hwX8beD1qYosZGJ6w1H9SJbKtG0_VtuuaMMM8l9q5AzI02weQhks68uj1tG79k8mcZWq-fexzgDqQ_8t5eWjhtyIjzmQVgUdryQYAn2pHrjGhNK2Q1dj7Vddm0I3ZBB0cca8Wsbu83w09ttarbLhSpJLYWAc17AGY4LD0iXLMlWtEuIeSTA_nEwR7jlQOxojEff55mG5BT90FuKN0G7aSnbCdOzTq93EwE9DRQIJks310r02zSVRZd3_e0_FBR3LgsSjczhVHvL5yBNaNCrOoPx1k2sABtUIt5AUDUYrAL3g10yfezM_2U2CvR4QzlPf1TYzpdIX7KPjlbBcF2Wwz6wRycZQG7hLnjO2l0dIEQwffTmqtpQNnKLskRTit5RG9It6MB_K158MiJcN5q_qDAmYo4yXLZR1_faoE2uoa2QZ0Ea7I0ywEuczJyPL3p-d72k4LRdw6V8MTYE28G_L5bNUs_7xRwk4zUBkhV4MCBRp97dW_sJRkM38bua4H_tw7pakbBiwFp_oetIZXZu05u-j5D5SwtUFQ3yi567r_ntbSAnGUBu4S54ztpdHSBEMH305qraUDZyi7JEU4reURvSLRVrEm1uBnGl63xKRoV9qcp8vRJuPMvee8mei79ODhFSFWsSbW4GcaXrfEpGhX2pyny9Em48y957yZ6Lv04OEVIVaxJtbgZxpet8SkaFfanKfL0SbjzL3nvJnou_Tg4RUhVrEm1uBnGl63xKRoV9qcp8vRJuPMvee8mei79ODhFSFWsSbW4GcaXrfEpGhX2pyny9Em48y957yZ6Lv04OEVIAkqVPorahvaHWiU0sYPk36xNLLIGG1EviZhUu7gVlc5-4OBf_ViPcXiCUec-0xy3glG5UEulMZ5sFDXcto_mmsNqF27M4mRJgfisNLAL2XEfIieWuf5NNUtpgptm3nqhGqeF5PpEWAXjlxsnwurNlN4e37y3-nZX1azoPYFcdMQWtpQUo_qqQDJf4MkKTLlqSo0no6jPrD3Gy0gOLhXKvzj1USsWKmcauSvtpuJQAEypb90dPb_gZILxQXXwIqLiqAgAAAAAAAAAtzQJpouFVpI4W6irPmdZ2_Z5glEEtR66igGDjLgVfbuytw0R-IFLxJnV-xd8Pk4yTQvJ5XPlNpJ4seEBUKSkimU2jQ0PvnFVPl00BxosOT5qUmg9Udw89aiaUmggL4KLcYbmhn6gs0tHv2EZywHdxFQAAAAAAAAAI8JE1PT5oUKBBEEZ1NIOXo-RRs6Wty3fCc10rYnsvFnB7pAqvdGGJ3n5ziLanz8K5Bk_2Zi1YStVaGH9A_XZhPsxf3VbBniw0zg85FO2ehBoQetKVU_oHtd-63loOXBCN08-7RViZJ9h9Cs54RyoxpPYwgbf6bJL7onEjYnSKYtkoZpSYHhBFzA0UeZ2ad5s5sTu_qxXF3pqz4IBEY3RxNOh_oeDtW6-FyxP0rDck8o_HgCxQ7f2Aqe3LEJpn-ll_s-5EmeEm18Kx-cJZ65XAexwrLtPikZ4cIExSe040GdYYUhYCt1sbcSgX9vmrjBRmHzLFPtIia6wr89Nzyu9o6MB_K158MiJcN5q_qDAmYo4yXLZR1_faoE2uoa2QZ0HowH8rXnwyIlw3mr-oMCZijjJctlHX99qgTa6hrZBnQTdLkNyOOz18CxhFcDMdKCg4qdjy2eJ5SEogIbDShm5fN0uQ3I47PXwLGEVwMx0oKDip2PLZ4nlISiAhsNKGbl_owH8rXnwyIlw3mr-oMCZijjJctlHX99qgTa6hrZBnQTdLkNyOOz18CxhFcDMdKCg4qdjy2eJ5SEogIbDShm5fN0uQ3I47PXwLGEVwMx0oKDip2PLZ4nlISiAhsNKGbl83S5Dcjjs9fAsYRXAzHSgoOKnY8tnieUhKICGw0oZuX4QEO13O1IoUzQNYkT4DVArcqWUnVdimNq9V89fBPD1ghAQ7Xc7UihTNA1iRPgNUCtypZSdV2KY2r1Xz18E8PWCEBDtdztSKFM0DWJE-A1QK3KllJ1XYpjavVfPXwTw9YIQEO13O1IoUzQNYkT4DVArcqWUnVdimNq9V89fBPD1ghAQ7Xc7UihTNA1iRPgNUCtypZSdV2KY2r1Xz18E8PWABBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGLDQ8AAgMEBQYHCAphMhBhM4UAAQIDBGE0BaRhMYcCAwQFBgcIYTIJYTOFAAECAwRhNAU"^^<https://w3id.org/security#multibase> _:c14n0 .
_:c14n13 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n6 .
_:c14n13 <http://schema.org/worksFor> _:c14n8 _:c14n6 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n6 .
_:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
_:c14n14 <https://w3id.org/security#proof> _:c14n11 _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n13 _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n6 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
_:c14n3 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n1 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n1 .
_:c14n3 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n1 .
_:c14n3 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n1 .
_:c14n3 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n1 .
_:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n4 <https://w3id.org/security#proof> _:c14n0 .
_:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
_:c14n4 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
_:c14n5 <http://schema.org/status> "active" _:c14n7 .
_:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
_:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n6 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
_:c14n9 <https://w3id.org/security#proof> _:c14n1 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .`;
    const nonce = 'abcde';

    const verified = verifyProof(vp, nonce, documentLoader);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });
});
