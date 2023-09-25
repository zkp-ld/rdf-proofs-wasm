import {
  DeriveProofRequest,
  deriveProof,
  initializeWasm,
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
_:b0 <https://w3id.org/security#proofValue> "ulyXJi_kpGXb2nUqVCRTzw03zFZyswkPLszC47yoRvUbGSkw2-v6GnY7X31hRYt4AnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
_:b0 <https://w3id.org/security#proofValue> "uh-n1eUTNbs6fG9NMTPTL98zwcwfA1N4GCm0XXl__t5tMKOKU1LBfwt1f7Dtoy9dHnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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

describe('Proofs', () => {
  test('deriveProof', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const challenge = 'abcde';

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
      keyGraph,
      challenge,
    };
    const { vp } = deriveProof(req);
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
    const challenge = 'abcde';

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: proof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedProof1,
    };

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1],
      deanonMap,
      keyGraph,
      challenge,
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
    const challenge = 'abcde';

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
      keyGraph,
      challenge,
    };
    const { vp } = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();
  });

  test('verifyProof', async () => {
    await initializeWasm();

    const vp = `
_:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
_:c14n10 <http://example.org/vocab/vaccine> _:c14n4 _:c14n5 .
_:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n5 .
_:c14n13 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n5 .
_:c14n13 <http://schema.org/worksFor> _:c14n7 _:c14n5 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n5 .
_:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n5 .
_:c14n14 <https://w3id.org/security#proof> _:c14n11 _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n13 _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n5 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n3 <https://w3id.org/security#proof> _:c14n12 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n5 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n6 .
_:c14n4 <http://schema.org/status> "active" _:c14n6 .
_:c14n4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n6 .
_:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> _:c14n5 .
_:c14n8 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n6 .
_:c14n8 <https://w3id.org/security#proof> _:c14n0 _:c14n6 .
_:c14n8 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n4 _:c14n6 .
_:c14n8 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n8 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n6 .
_:c14n8 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n6 .
_:c14n9 <http://purl.org/dc/terms/created> "2023-09-21T11:36:23.663929856Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n12 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n12 .
_:c14n9 <https://w3id.org/security#challenge> "abcde" _:c14n12 .
_:c14n9 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n12 .
_:c14n9 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n12 .
_:c14n9 <https://w3id.org/security#proofValue> "uomFhWQnaAgAAAAAAAAAAiAvTWnfhK5FK9n4FTbueRNfjipNVS5MNyvEPc2IJOuvQ0C3fp8hCuAIRc1_Lhf-Atw-gSU7LG7ia71FC2ozwOABP3GLWPBmU3fwEu7ooM5PYmQt1U9zsIGB1RVtG-T8huOdclYb-wiZFb7of3H6cRIcy7ujTzwgeTisDURUIZ18uiU1d5waitcTMFppTyi2StbtPjPxCObRd68AaVop3K37J1HCIIr9FjynFecH-dn3druVBnHgpeY9bKuOnneAHAgAAAAAAAADFAMrFjLAwFzeCag9JnfvJa4sib8jnC3F-GVzu-pEVaQqLd9maCNxm4qe3qvHxhjo8svPmuMs4zGJLZ3h7FdpzlBmWzGSPL8_bZpAlEKSxwR5jxRI8gplwEN9rL_TunBFRPVTAmJH0s-4Z_0M42LTwJQAAAAAAAADmpxFadg9i_CvnVqqKKpe5DHLYPin12qA6wrZqF3usET07re5L_LAS1BgfnYtvAp6_-7fpQ_v_2YGnLO4ouWJBseiFcR7PYBxwGC7HdgGHM-Dq4yXDSQJRRQS0Onq-3SPVj0Emqqy5Prpm_NdLIi8jlLhtec1TobFLMMKxiKBFJm6X1TmNITbne8Zb4fGyVFw7VVHlgO8yz6gKDC4TcvcnMas_hU-65b_XrSi7yNsvW-hms1069AvacbXskBX7rCncX8e-bqJBDtnvVB8rOWbALk8sdn8mXIbKucO3KSddYrHohXEez2AccBgux3YBhzPg6uMlw0kCUUUEtDp6vt0jxyhevJbcHbchu617fw0K07-7unaVXP-Qxd0NFN0GO1Cx6IVxHs9gHHAYLsd2AYcz4OrjJcNJAlFFBLQ6er7dI85d36Xq0iNf_xqFAttV95nqPmEG0d_KGhnJsemmx4hHzl3fperSI1__GoUC21X3meo-YQbR38oaGcmx6abHiEex6IVxHs9gHHAYLsd2AYcz4OrjJcNJAlFFBLQ6er7dI85d36Xq0iNf_xqFAttV95nqPmEG0d_KGhnJsemmx4hHzl3fperSI1__GoUC21X3meo-YQbR38oaGcmx6abHiEfOXd-l6tIjX_8ahQLbVfeZ6j5hBtHfyhoZybHppseIR_nTD-EjxlwSJlRPVtOJ9Cq-G2eFd5d9y9xoRVW98vEod8cSVxq5B0R9iloenQr3cQjaXhKj0AYNBotZH02xQlHe4F2k7PxanS-tREDTxviA5QjQrq54mdF-6E8glu-ODMcoXryW3B23Ibute38NCtO_u7p2lVz_kMXdDRTdBjtQ702-cGYYqPreCy1VetrT_0F956exjmhf4ffZrO0auxI98x_AkdgFgm6wSV1LnkJ3cfVy7n5uRxGQ3nRYA0JoJPX47fF5HSDae4TxE9Ifh4erRTMRmP8e1wszyq4zTn0FhhvLx8m17KaLFj_WSi6QN-x_DuBncILmYS8RMCN4_gms3ZRpOnbHZyeusSASQf_HVjUxTAwnUw7evRwDDtGXJDxKRbHgljw6HpSXNyJKBACHWrMXsoxTMjaIqQ0NfSRY1Y9BJqqsuT66ZvzXSyIvI5S4bXnNU6GxSzDCsYigRSYOzIGG_xWlyKrgYn-0MR2qh49lq2Gr4e2H_UKoSjgFT81TCksS7oc2G5JmKn5udpHYWDcOyFU8H3jKvtvb38BK0fpR0B5u0xmPDecPPnndOuXueINPTVCwyOoXnkJaox1-4DKoKPel8efuFjMcYRVm0y5DwFkvfWNFaNnxsHU7NdWPQSaqrLk-umb810siLyOUuG15zVOhsUswwrGIoEUm0gFo3d0Q169csX-agPVv-lTnWPiBSjMnalSiSyVX5QHSAWjd3RDXr1yxf5qA9W_6VOdY-IFKMydqVKJLJVflAdIBaN3dENevXLF_moD1b_pU51j4gUozJ2pUokslV-UB0gFo3d0Q169csX-agPVv-lTnWPiBSjMnalSiSyVX5QHSAWjd3RDXr1yxf5qA9W_6VOdY-IFKMydqVKJLJVflAQCsfuTQjkFAt7HLPg5IlqNbtDUXlV8BSo1MO-TnkS5XZa7O2BcJjzR0fc8VHkioAx-ThPGRsf9IMPQU37SQH8fxpAf9irC-ghKxPvaH6Q1vKU8mmSikLMI7XcxstAyrghaUfEzS6V0G4bFYLJ86vyPi83tBGDDy_RLtN_er8NxgZUNyql_8ra_GRUpm62E09g2V3t1H_bL2FHMCfSok3__0xTGHSwbIgIvxnbpHADwih2jfLXmcN5_iDnFWVjVQwaMCAAAAAAAAABtEnFz-_fsWTa-SSiLsOtPKVAqI81CVVVlS8FoNMvxWw87N0t5OEqjlL8XwC_5lsHq5SaaNRHd7YK5DX2vMewCshM-m4EVeP4feH7p_12qH_sI5ME1L4JxDuFG962JrK-SZJiEGnAMwJOyu0B0ZV9kVAAAAAAAAAORW8JlO-6GI_HPv1qgITpvjmIFrjq5eyQORDYRLSwcFMeiHbCAvMYSrctuAmbaJCebGblJEW4wu4juvrcVDzD9k12E4-FoR04J32Pgf7pXME22Dx6Un5Bqcj0_l97X5HTmCaL92l3mE1Vkq1zi5anQkik1NkeqiXJKVANp8alM4U4igyyzi1twJQtj5Zw9ExVsohHko3hQA2kdiIleLxTpa84H8gYfOVdR03LO4OBs6iSSKIWDB55OQnWAXNw-YZ6Qbv2eP5Ue9wWhez9FFb6YoEr7xTLPAArX9Tq_NEFpT1Ep03asgrIPp0p7CU767k6hONY-m8vgJlqSPoS4cti8OzIGG_xWlyKrgYn-0MR2qh49lq2Gr4e2H_UKoSjgFTw7MgYb_FaXIquBif7QxHaqHj2WrYavh7Yf9QqhKOAVPB70w7NJVMYXUBb95-yRBNxhkzVaR4pNYaQ4_mezfdBAHvTDs0lUxhdQFv3n7JEE3GGTNVpHik1hpDj-Z7N90EA7MgYb_FaXIquBif7QxHaqHj2WrYavh7Yf9QqhKOAVPB70w7NJVMYXUBb95-yRBNxhkzVaR4pNYaQ4_mezfdBAHvTDs0lUxhdQFv3n7JEE3GGTNVpHik1hpDj-Z7N90EAe9MOzSVTGF1AW_efskQTcYZM1WkeKTWGkOP5ns33QQ4wYh-C5BSpRLBvMrrVj36YelFsp5y7Jq6zAvlkVICT3jBiH4LkFKlEsG8yutWPfph6UWynnLsmrrMC-WRUgJPeMGIfguQUqUSwbzK61Y9-mHpRbKecuyauswL5ZFSAk94wYh-C5BSpRLBvMrrVj36YelFsp5y7Jq6zAvlkVICT3jBiH4LkFKlEsG8yutWPfph6UWynnLsmrrMC-WRUgJPQEFAAAAAAAAAGFiY2RlAABhYoKkYWGLDQ8AAgMEBQYHCAphYhBhY4UAAQIDBGFkBaRhYYcCAwQFBgcIYWIJYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n12 .  
`;
    const challenge = 'abcde';

    const verified = verifyProof(vp, keyGraph, challenge);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });
});
