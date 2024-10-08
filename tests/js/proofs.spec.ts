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
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
# issuer3
<did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
<did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z488w754KqucDkNxCWCoi5DkH6pvEt6aNZNYYYoKmDDx8m5G" .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC74KLKQtdApVyY3EbAZfiW6A7HdwSZVLsBF2vs5512YwNWs5PRYiqavzWLoiAq6UcKLv6RAnUM9Y117Pg4LayaBMa9euz23C2TDtBq8QuhpbDRDqsjUxLS5S9ruWRk71SEo69" .
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
_:c14n1 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n12 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n12 .
_:c14n1 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" _:c14n12 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n12 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> _:c14n12 .
_:c14n10 <http://purl.org/dc/terms/created> "2024-08-23T02:45:49.981532998Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n11 .
_:c14n10 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> _:c14n11 .
_:c14n10 <https://w3id.org/security#challenge> "abcde" _:c14n11 .
_:c14n10 <https://w3id.org/security#cryptosuite> "bbs-termwise-proof-2023" _:c14n11 .
_:c14n10 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> _:c14n11 .
_:c14n10 <https://w3id.org/security#proofValue> "uomFhWQe4AgAAAAAAAAAAlWj7ySOnU5mw_rG271EltSGHfh0Sabj6_FBXzZ7GBT7TTXM-OJk2y-UjU8hAYyS9p5SkDSPYysuFjUy9RUNu4ypsNdZrRJX2E3TmTg-186q3jvPKExzchRPg7LrE6pWeqzMXck8jrsaUR1_zIsH6KKuTO5gnDEOV4Ufg8zCm7nDLetSoflGoX0d-AUrr9-C_j1WOnJ0-lOnlLr3Mg5hOjxDktjaDvUdwDJ36rFx7agxBvtUKa7deW1Ta-Vq1vFiiz2v7ALxtyrm5rzB1JBRdfsJet5Vb_FX3UQlG6TclU1KscOYL5gf92CsgvzkdItKJFaQmlbUaJ1G11h26l8lyRafN9HGrj29J4Uw6JxaWUcC-53KvYV7utm2rFr6hTN04SVl4k17LODqbiVuQ9BOYegABFwAAAAAAAAAAAAAAAAAAAEfN2HoEQky0MByRnjeWvLtZSGEhIAl4_eanyq9fTe9AAQAAAAAAAAAnJf1hjwcmRG9q37lvJE0D8YnXbv7DE94eFGr6hqNvGAIAAAAAAAAAX5Qjv-i24vQ4ksBHab08Nx2ubjuPAzhSvCaAOAlxRzUDAAAAAAAAAP7Yh-Mk-7oXrq5rka64MdYPtqgogXKNFwTw4YTBDDkkBAAAAAAAAAB6r3ptkYeMr6n3iF_bffXJl3oy7Vr17KHNZhihkJHVGQYAAAAAAAAA_JhzhRf5RjnOAJiYUB8ckVCm7t9JivkuHenkqeacSR0IAAAAAAAAAHuTD4mphlQyF3Y5tliZ3lYu9sKgPM_7U_itTfbIRnFvDgAAAAAAAAArpeH4MJzWqp1bzV53K-OYOYxcBwrFHeHMV6rJvEmxTw8AAAAAAAAARPVate_53JtTi530guf47C8pVN3pTohKmMVOE_nCzksQAAAAAAAAAJpdx4qaj1T1x8aLf8KCCE-ipO3ctzqtEI8WaxeIJzM3EgAAAAAAAAA3ZI0DRda1lDRTW9Bd_zkfZNg2hDBxqNIEXxaU7c4ARRMAAAAAAAAA6PcPvPkt4h4AoK17oQyjX6SzFGCocQY9yqbX8LTlmQsUAAAAAAAAAAE43979Qxp3ga1ZRpCKdM9fNmRBCsp9eQR9ydspesshFQAAAAAAAADOMZpaqHP6QOFdbVEuU_ZWDttdvOZSwlmFlk0XIyxEPBYAAAAAAAAAK05aN4CYMGQuKE116IZ0048SKqI_NOQ2Zqnh2Lwh7Q4XAAAAAAAAALX_BVDxoVLV2jwcesBstib4Qy4YFa7qyFsIrIJ-u3UZGQAAAAAAAAA0R3_Q5disVcF4K-AkQb_NKn2d18wpUuck2MVrLTH2DxoAAAAAAAAAFGrZ3fGrldBxfZalXu8eXfXb5OA-YEJfU7RdmYjsGAkbAAAAAAAAAAIQvfDpfxqY39XTkAJNYXvb7CKGZBY07bWE9B2qQG4sHAAAAAAAAACQ4-GIwNpLk7jQgug7LpoDrci6Sl54wZcbM-N-Ch0FXx4AAAAAAAAAt0WJscwZ7p22uxryXz3j6GdbARRmQJ0BH1RXuTlHNWUjAAAAAAAAAMW_o75vhhse34F_jGkABqr_AZGBX3YktM1LlK629V5lJAAAAAAAAACqe0mNBT7hWRZYmqrqzlhtPDDpEvWTCjeCLWhLzd8_EyUAAAAAAAAAAIxRE6_DuH0_ROAz-iV5j4yYsqr0xOfpjb00o--YJumt8jHt_iMy7xJE3zgJnR8i_q-_NGjQELZv9cVvbXyjXB4wc6vy1Oz9h-mclraqgHRaaALlnzqiX0VCoZRiLxZUKLHL4UyVFnqfCMmb_iAJI8Qp4VVuZTCSpHv0p0oO-4ySavNJfbSZhSnV8PpOCCFmTY9FKdqufrgWow1GWTBzYrQ_fQvaLJJc94kSoBR_xNR6QfC1UtPIPP9r05ubP2Vi7CWvzZctu5W5z9xYsP1inIchKJ-uhmXf2yxC2lVKxTlA1UfUUvnysTF8cWfwdoIR-8Mzjugdy8HwsqMVXDpZbxqiuAl3770_97VvG7-bLPJj35GhJmUwK8Tbw_xBFoMz9yWTIew6ivMP3F-9W2hCyzQAAQoAAAAAAAAAAAAAAAAAAAC7ZnA6NT9sxFpIobbBS0k0psK2jiaBJNx94yPcVxtKLwEAAAAAAAAAWraRE_rcXPgS8LeUoUxBkarEo9bqt_37Hb5Ri1IkDG0CAAAAAAAAAMxtH--szMw0uIlh-tM0zFLL7Q2_Vztj4qTOCAjWtFMvAwAAAAAAAACwgpD-v2spR63ppnFX8hBOFqIb39hC7iEqdJfkQ836BAQAAAAAAAAAcUkHxmQmHRWYaaGltyJxIVBhs7yTMUJARzhEo3ki5k0FAAAAAAAAAGkugnPRZhl3C_iCEHmZzIRAgkP6rbaUduaZRevg4wEgCAAAAAAAAABXL-gTFxBIsBE7O6ffqwXWm-vhSAZXXehyUn3bMLtoOw4AAAAAAAAAyK8UZpWesdRVp1YV4JWilwSRahgrir_-V4iNyIPHfE0TAAAAAAAAAJeY3RnElczE-wb4LYg9XOhSKI2xedR3m20-k92ZxPEzFAAAAAAAAADwsAEZU2x19ljCfYuPGt36dsYVRBMBGPFqVLwYT1FKYxUAAAAAAAAAAABhYoKkYWGLAAIDBAUGBwgKDQ9hYhBhY4UAAQIDBGFkBaRhYYcCAwQFBgcIYWIJYWOFAAECAwRhZAU"^^<https://w3id.org/security#multibase> _:c14n11 .
_:c14n13 <http://example.org/vocab/isPatientOf> _:c14n9 _:c14n5 .
_:c14n13 <http://schema.org/worksFor> _:c14n7 _:c14n5 .
_:c14n13 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:c14n5 .
_:c14n14 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n5 .
_:c14n14 <https://w3id.org/security#proof> _:c14n12 _:c14n5 .
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
_:c14n3 <https://w3id.org/security#proof> _:c14n11 .
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
