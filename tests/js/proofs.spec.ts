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
    const proof = `
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
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
    const proof = `
_:6b92db <https://w3id.org/security#proofValue> "uhzr5tCpvFA-bebnJZBpUi2mkWStLGmZJm-c6crfIjUsYTbpNywgXUfbaOtD84V-UnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
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
    const proof1 = `
_:6b92db <https://w3id.org/security#proofValue> "uhzr5tCpvFA-bebnJZBpUi2mkWStLGmZJm-c6crfIjUsYTbpNywgXUfbaOtD84V-UnHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
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
_:wTnTxH <https://w3id.org/security#proofValue> "usjQI4FuaD8udL2e5Rhvf4J4L0IOjmXT7Q3E40FXnIG-GQ6GMJkUuLv5tU1gJjW42nHL4DdyqBDvkUBbr0eTTUk3vNVI1LRxSfXRqqLng4Qx6SX7tptjtHzjJMkQnolGpiiFfE9k8OhOKcntcJwGSaQ"^^<https://w3id.org/security#multibase> .
_:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
`;
    const disclosedDoc1 = `
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
    const disclosedProof1 = `
_:6b92db <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:6b92db <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:6b92db <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b92db <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:6b92db <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
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
_:wTnTxH <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:wTnTxH <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:wTnTxH <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:wTnTxH <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:wTnTxH <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
`;
    const deanonMap = {
      e0: 'did:example:john',
      e1: 'http://example.org/vaccine/a',
      e2: 'http://example.org/vcred/00',
      e3: 'http://example.org/vicred/a',
    };
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
_:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n11 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n11 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n11 .
_:c14n10 <http://example.org/vocab/vaccine> _:c14n5 _:c14n4 .
_:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> _:c14n4 .
_:c14n12 <http://purl.org/dc/terms/created> "2023-08-16T03:12:49.668550444Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n8 .
_:c14n12 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n8 .
_:c14n12 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n8 .
_:c14n12 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n8 .
_:c14n12 <https://w3id.org/security#proofValue> "uomVwcm9vZlkJGgIAAAAAAAAAAILzpesgeNjAWzelqJOdlEF4OyouKLi0QyZsftUPCdCsgg4ydsvcOJUbk9cJFNUQZrKNOFs9CP0qHdR_QbYZvhx804iCnnQLZ_Kg0Z7V8Y0pNPgffwtcI8_62f5Nm4K7aaRnLRqEMi_Na4_IRoEPea33lAnbmO2ohj_ogmTVk_G1qKHQuKnRvXnANmpjPHiLSIjVnazDxU7GARWkXoBZiTWjT92XkNVHm9_IdX3qin1Z6bdaYyMEaxCCso5jx1FKzwIAAAAAAAAADMpPluiMSFTtkKtzAP7VLPqOCDMNQmIeO5wms4haGxNiEj_FtTwxi607tO_3MlsJ7G-MAqgiTmvHP6sw-I1QDJCi08G0IRs6xCqI8PDoolZoI1z0zraLVpe9R1WXNPMKmzEQ-zD_KrtyX3ydKl8Ptx8AAAAAAAAAFHTUF8bbWiCR7CLE0Ky3Fi4VfQhz1SgCagyJhVih_klev2vGSmuWDW34T3mitRqqGI9fuv6gjvUmukSBX7TQKdUOtdpfqHZtjLGSoCJ774sfolMKCbtNfm8XJU27Xvtb-8hzv7YRI9YCrtlMzWMGhxeN8KbX-ZiQMU3DUzIT7GysV8lxr12r4CGvVYspGEE4YkRlwXWEugmpsFSV-aVrEN0OUQ7U5L0TsNfp9FDnKVfMg2r_XIhFdAM2UD8VFpVNVAHMqjQnkAmQkuW94SO5oOMPOhT6zCnSpJZeL7InRDzVDrXaX6h2bYyxkqAie--LH6JTCgm7TX5vFyVNu177Wy2UIefOpxbMsC9C4_ZlfUW6fcxzn2yrLA3VjjeDf-xPLZQh586nFsywL0Lj9mV9Rbp9zHOfbKssDdWON4N_7E_VDrXaX6h2bYyxkqAie--LH6JTCgm7TX5vFyVNu177Wy2UIefOpxbMsC9C4_ZlfUW6fcxzn2yrLA3VjjeDf-xPLZQh586nFsywL0Lj9mV9Rbp9zHOfbKssDdWON4N_7E8tlCHnzqcWzLAvQuP2ZX1Fun3Mc59sqywN1Y43g3_sT71Wld_dO1Ph0jjjrkmQJIDdB80VogKnSHdInKFC0rtqDe1EPR6qzxxyLVEes4ys-OF2xVIjSQ2eM2QJe4Y9Vmmz_pOAcM2hWLvY0nO7UJi3M1XLkzmlLbGQBDoR28icEQDgForj-ZjE5_6muJ0f4Xlio8CW8OOgBGmYvVO4I48lL8C0Cm5GkA-4eRqzpl63BlP4_19K-G_v9ui7RU0bghDdrwvwrTcNNckdJg-T3oGL5w6rIdXRnjf7KDw16OszcvvIc7-2ESPWAq7ZTM1jBocXjfCm1_mYkDFNw1MyE-xsaT4CInAfZpLPFP6_ZJ8JabjyJt8u2RtLkBQWucxUjFiLoxJVJNIJZuUd9N4CNIRpCivkZhH0dDumSOIyUZpRP-2qHctcNdtDtbotypp17Vqqi3L3u4w_5aq8A5MWI0kZaT6eI-KdnePqpF5Uu8Rg8ykme6-j5Uf9TFgBAwrrvUf7yHO_thEj1gKu2UzNYwaHF43wptf5mJAxTcNTMhPsbJ-weENC72FgB4rZvRNKluCpua5CHs3PhndXyJTO-78In7B4Q0LvYWAHitm9E0qW4Km5rkIezc-Gd1fIlM77vwifsHhDQu9hYAeK2b0TSpbgqbmuQh7Nz4Z3V8iUzvu_CJ-weENC72FgB4rZvRNKluCpua5CHs3PhndXyJTO-78In7B4Q0LvYWAHitm9E0qW4Km5rkIezc-Gd1fIlM77vwgAp96NoMD4L_PNjc4amwG_T9khjcCiJ3f6wBGo2pDpthmhppfpnnUMpDgY0Z4TWSY-rPvNt6bWHuZ22YGQPqhcedEH-s4MzcCnOw2x2khdjk1ZNJmXjDtRBBp00ZouIbr-g08AO0EeEgmIYN4NExm3zaD1LIdRyT4qaBdtjP0Cnp_UXu6k0oG75k-2DWWpIxWVkI6WcaArlo4u7nnIEbsks0s9vqyhertZ7NahIDTksKYbJxQ9ervfBQG30ZEMLdegAgAAAAAAAADhRIXAJgSyFo-bMFjBOp-l7taq8s2bBTajaRHfYCOvVu_SKea1ghAyYJ2FoTdimcmYYj-WfLdD3McyT63UITNWsXn64FxlTuqf5tQh-Yyadly4qb3lafQB7-_WfoT_K01X6klrgVp2Mc7np4_bmcMcFQAAAAAAAAC2zYWf4D9h1zvRRH_AeLBCCwoQb4slS1ACAxYG533-YSo1_1pC3IxyHS-tWxI-_VQoExa9z50QElsMmELjQn04WFi2_kW2slPL4gkyk3LgSUNl-pQmZdqiNxABuw3VLWOoSSn1n1GC2Q1lW9Zi4qTnOEVWqc3Bt-SHZP4CYeCII_6slx1VaIACRCeSnwrwP5mQga5jUS7DgCGyn-vzqZYxN8pOdAyrojbWZex6w2WWklTrP4pGLstSB9yGv9DdWB9MmpD2lWq4Tb4yMeeoVPtfsmnuU3I4ajPd3q4VWiyQGWiUVt91u6ab_a4_wk_Wl_cFiLoP-LDa5W_cL9oMJGhTaT4CInAfZpLPFP6_ZJ8JabjyJt8u2RtLkBQWucxUjFhpPgIicB9mks8U_r9knwlpuPIm3y7ZG0uQFBa5zFSMWBdxSyAWDqeayQdq9cJXx7HgAp_L7ZjNnwb88H7357NKF3FLIBYOp5rJB2r1wlfHseACn8vtmM2fBvzwfvfns0ppPgIicB9mks8U_r9knwlpuPIm3y7ZG0uQFBa5zFSMWBdxSyAWDqeayQdq9cJXx7HgAp_L7ZjNnwb88H7357NKF3FLIBYOp5rJB2r1wlfHseACn8vtmM2fBvzwfvfns0oXcUsgFg6nmskHavXCV8ex4AKfy-2YzZ8G_PB-9-ezSqDjEQaYgzNsg-fYggN4G1Ldl8gDUfgb2RXxG63l8qwdoOMRBpiDM2yD59iCA3gbUt2XyANR-BvZFfEbreXyrB2g4xEGmIMzbIPn2IIDeBtS3ZfIA1H4G9kV8Rut5fKsHaDjEQaYgzNsg-fYggN4G1Ldl8gDUfgb2RXxG63l8qwdoOMRBpiDM2yD59iCA3gbUt2XyANR-BvZFfEbreXyrB0BBQAAAAAAAABhYmNkZQAAaWluZGV4X21hcIKkYTGJCgwDBAUGBwACYTINYTOFAAECAwRhNAWkYTGHAgMEBQYHCGEyCWEzhQABAgMEYTQF"^^<https://w3id.org/security#multibase> _:c14n8 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n4 .
_:c14n13 <https://w3id.org/security#proof> _:c14n11 _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n6 _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n4 .
_:c14n13 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> _:c14n4 .
_:c14n2 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n0 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n0 .
_:c14n2 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n0 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n0 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> _:c14n0 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n3 <https://w3id.org/security#proof> _:c14n8 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n4 .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n7 .
_:c14n5 <http://schema.org/status> "active" _:c14n7 .
_:c14n5 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> _:c14n7 .
_:c14n6 <http://example.org/vocab/isPatientOf> _:c14n10 _:c14n4 .
_:c14n6 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n4 .
_:c14n9 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n7 .
_:c14n9 <https://w3id.org/security#proof> _:c14n0 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n7 .
_:c14n9 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> _:c14n7 .
`;
    const nonce = 'abcde';

    const verified = verifyProof(vp, nonce, documentLoader);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);

    expect(verified.verified).toBeTruthy();
  });
});
