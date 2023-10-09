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
_:b0 <https://w3id.org/security#proofValue> "ui_TYLyZXnF1LRhdzEDrKiAWA0Tbrm1GmCHXBVnX39BTBnIbdFLc9p2jRAw0H4jzznHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
_:b0 <https://w3id.org/security#proofValue> "uoB9zdaILAqel15HTh6MtIkDZjoeQn2g-fqACEgZvKNMRbgGqTOmNDclM2Pv-WF7BnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
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
    }).toThrow('RDFProofsError(TtlTermParse("e0"))');
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
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();
  });

  test('verifyProof', async () => {
    await initializeWasm();

    const vp = `
_:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n10 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n10 .
_:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n10 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n10 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n10 .
_:c14n11 <http://purl.org/dc/terms/created> "2023-10-06T05:40:05.941640167Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n13 .
_:c14n11 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n13 .
_:c14n11 <https://w3id.org/security#challenge> "abcde" _:c14n13 .
_:c14n11 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n13 .
_:c14n11 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> _:c14n13 .
_:c14n11 <https://w3id.org/security#proofValue> "uomFhWQnaAgAAAAAAAAAAlWj7ySOnU5mw_rG271EltSGHfh0Sabj6_FBXzZ7GBT7TTXM-OJk2y-UjU8hAYyS9p5SkDSPYysuFjUy9RUNu4ypsNdZrRJX2E3TmTg-186q3jvPKExzchRPg7LrE6pWeqzMXck8jrsaUR1_zIsH6KKuTO5gnDEOV4Ufg8zCm7nDLetSoflGoX0d-AUrr9-C_j1WOnJ0-lOnlLr3Mg5hOjxDktjaDvUdwDJ36rFx7agxBvtUKa7deW1Ta-Vq1vFiiAgAAAAAAAACTBwTiEdk00-BvIIfqz8oDk2xDYnTLtUDSu6P0xdL0RjQuKBHV6xaVhb5qoBYP-IdGKx2-2Sk21iHIjrVlQFBup830cauPb0nhTDonFpZRwL7ncq9hXu62basWvqFM3ThJWXiTXss4OpuJW5D0E5h6JQAAAAAAAAB-w7b_iVOFQAQGHgFpp06QV6gwCTxWfLJyxKxKSK-kHpm0wTrncrlMfDmqvHqaHWlcXvv6p7dTHnX0tJLWYC9XUt2I6oyQBKKHQlBI7ZDXkk0Xq9P7QGXrH48bcAW7dTbHdgGgIIBxJ3n8mg1zvsidRWNMNUJx7nHIWxKWIRe5BGqk0y5xBZvij7h_8R64Vw4RfbjtajslQPUN0fiu3s0qP0Iq0VyjWycJ6uAn8i4kZWNWbafJLH8ki8rz_H_o3zC0n0S_-meUXC7Ok2cVmKmcZrZuC-sjgMLdJbVjhqWUD1LdiOqMkASih0JQSO2Q15JNF6vT-0Bl6x-PG3AFu3U2R3eQBscDGEj2SejHCKIW5AQ3vI2u81WOkaojzcsfMR5S3YjqjJAEoodCUEjtkNeSTRer0_tAZesfjxtwBbt1NlltLFFHMcT568va2232ixBc7DF1IviaZJdNvtrU1nxqWW0sUUcxxPnry9rbbfaLEFzsMXUi-Jpkl02-2tTWfGpS3YjqjJAEoodCUEjtkNeSTRer0_tAZesfjxtwBbt1NlltLFFHMcT568va2232ixBc7DF1IviaZJdNvtrU1nxqWW0sUUcxxPnry9rbbfaLEFzsMXUi-Jpkl02-2tTWfGpZbSxRRzHE-evL2ttt9osQXOwxdSL4mmSXTb7a1NZ8anaD_nngpqe5xaQdji-u3evtHCq1bi56QEEZ6eyhzJhQhV79oieifauuxhKLxl3re4PJGFwyCXpXH6Bgi7eedVhKPDD2T3YTIj22AH4inhAyV368j4d3voLJAa4inSwSXUd3kAbHAxhI9knoxwiiFuQEN7yNrvNVjpGqI83LHzEe17WRQdZOAXg-5RYkYZm1ubixq0p0HoNmrqa-L4hCSjEg-SkiGOJYUfBxFAgkYTauH2E2FLz5_NHR4g0mxD2_NcVmZ1okq1eLeIdzUV9RPd4cUbr5uiGObyTu2miM3SsUboOemDnsRSTr7yilMe1x8WK00oIqAJ3tLt71sr2fjSjdAXrIJwtaz3pK0--RrrgOzC2OWjzZWOna0i5WVnhcZZ_SUYwus1fQv3H5VCsXgIA0Sztj5kM0msSkvOQ9sc4bx3YBoCCAcSd5_JoNc77InUVjTDVCce5xyFsSliEXuQRUD-bXOni6wTd1ZJKGXVsu3cDKGrwRcMLtUcLCmo-bCLW73RuCJOGzemtQ-WQtWEtPjfuwiuVWJkV5o152B1BpBgNslfYVji5qEQYcG9iz0suNjVlTC8mcKN4vDspNBW71xFFH-CBvYGoSHgKZ3l0tIJylcX5FMV_FjZO03bLqO8d2AaAggHEnefyaDXO-yJ1FY0w1QnHucchbEpYhF7kELS0TeuolCiEnceAsJagqrgL7AE3FaIpDybD_b6xVaFstLRN66iUKISdx4CwlqCquAvsATcVoikPJsP9vrFVoWy0tE3rqJQohJ3HgLCWoKq4C-wBNxWiKQ8mw_2-sVWhbLS0TeuolCiEnceAsJagqrgL7AE3FaIpDybD_b6xVaFstLRN66iUKISdx4CwlqCquAvsATcVoikPJsP9vrFVoWwCMUROvw7h9P0TgM_oleY-MmLKq9MTn6Y29NKPvmCbprfIx7f4jMu8SRN84CZ0fIv6vvzRo0BC2b_XFb218o1weMHOr8tTs_YfpnJa2qoB0WmgC5Z86ol9FQqGUYi8WVCixy-FMlRZ6nwjJm_4gCSPEKeFVbmUwkqR79KdKDvuMkmrzSX20mYUp1fD6TgghZk2PRSnarn64FqMNRlkwc2K0P30L2iySXPeJEqAUf8TUekHwtVLTyDz_a9Obmz9lYuwCAAAAAAAAAOlK1niDJgDT9pxIwsMeCg3yNSt7nzQ_Ja30N2HYcts0K3EQ_3v04hCcZNINbmYwTZ98XSwMgURCHZaIV-7RvQeiuAl3770_97VvG7-bLPJj35GhJmUwK8Tbw_xBFoMz9yWTIew6ivMP3F-9W2hCyzQVAAAAAAAAAGNy0ZdMnEafcDVeEYYXTavNQsN_5yO8taRWovPJyGUU0quwoJjxTyu_wstf4jKhU32wUodzmFoPOL_qMVLX-hXbLtdBit55MNFE2mgjaOWUWAbk0RVpQrdGXSAzxXnvJ8t3NM6QHw22JEN1L_fCE1C369SkBPsAlRffB8eW8IJrw05KiuEou1_vvDGtEJnbLwX1Orps8mkJQVQ-ZM6BVw7RSvcFFAs3syJC3iO8smoCzr3qK9ACRjA7azFlBNONcbKyqbOczr0k86QWPPuYY7CjAXg73OszTc4SVhs4_oxaKnoln7pNO2VB0NjFbn2mrcrRFc_hJlLnilmo4Uf0kiZUD-bXOni6wTd1ZJKGXVsu3cDKGrwRcMLtUcLCmo-bCFQP5tc6eLrBN3VkkoZdWy7dwMoavBFwwu1RwsKaj5sICvra712P-6jgiuZixbofwrWQdF_3NrtGO6QFRbq7YB4K-trvXY_7qOCK5mLFuh_CtZB0X_c2u0Y7pAVFurtgHlQP5tc6eLrBN3VkkoZdWy7dwMoavBFwwu1RwsKaj5sICvra712P-6jgiuZixbofwrWQdF_3NrtGO6QFRbq7YB4K-trvXY_7qOCK5mLFuh_CtZB0X_c2u0Y7pAVFurtgHgr62u9dj_uo4IrmYsW6H8K1kHRf9za7RjukBUW6u2AeYUx4jiPSsMEUawCLAAqtsBaRY7_AujfoOeDybUPZNA5hTHiOI9KwwRRrAIsACq2wFpFjv8C6N-g54PJtQ9k0DmFMeI4j0rDBFGsAiwAKrbAWkWO_wLo36Dng8m1D2TQOYUx4jiPSsMEUawCLAAqtsBaRY7_AujfoOeDybUPZNA5hTHiOI9KwwRRrAIsACq2wFpFjv8C6N-g54PJtQ9k0DgEFAAAAAAAAAGFiY2RlAABhYoKkYWGLAAIDBAUGBwgKDQ9hYhBhY4UAAQIDBGFkBaRhYYcCAwQFBgcIYWIJYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n13 .
_:c14n12 <http://example.org/vocab/isPatientOf> _:c14n9 _:c14n5 .
_:c14n12 <http://schema.org/worksFor> _:c14n7 _:c14n5 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n5 .
_:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n5 .
_:c14n14 <https://w3id.org/security#proof> _:c14n10 _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n12 _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n5 .
_:c14n14 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n5 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n3 <https://w3id.org/security#proof> _:c14n13 .
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
_:c14n9 <http://example.org/vocab/vaccine> _:c14n4 _:c14n5 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n5 .
`;
    const challenge = 'abcde';

    const verified = verifyProof({
      vp,
      keyGraph,
      challenge,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });
});
