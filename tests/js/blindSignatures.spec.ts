import {
  initializeWasm,
  requestBlindSign,
  verifyBlindSignRequest,
  blindSign,
  unblind,
  blindVerify,
  deriveProof,
  verifyProof,
  DeriveProofRequest,
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
const proofWithoutProofvalue1 = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;
const boundProof1 = `
_:b0 <https://w3id.org/security#proofValue> "utXwiR3cqE_vytaKRk1jO5bijPewZ8Vx67WqHBjJ1TAN8BoEnhdu7zXyZ1WTYuLHqAWQCF5cBR1F0h3FXGsm2xh7Fafg49VG-Slte0XnTgDzpRqn0nqhO4I57s-b3TPVbA_t5uyJnGllyB6QcwVtRQA"^^<https://w3id.org/security#multibase> .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-bound-signature-2023" .
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
const disclosedDoc2 = `
_:e1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
_:e1 <http://schema.org/status> "active" .
_:e3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e3 <https://www.w3.org/2018/credentials#credentialSubject> _:e1 .
_:e3 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
_:e3 <https://www.w3.org/2018/credentials#issuanceDate> "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e3 <https://www.w3.org/2018/credentials#expirationDate> "2023-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
const disclosedBoundProof1 = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-bound-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
`;
const disclosedProof2 = `
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-03T09:49:25Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
`;

describe('Blind Signatures', () => {
  test('blind sign and verify', async () => {
    await initializeWasm();

    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'challenge';
    const { commitment, blinding, pokForCommitment } = requestBlindSign(
      secret,
      challenge,
    );
    expect(commitment).toBeDefined();
    expect(pokForCommitment).toBeDefined();
    if (pokForCommitment === undefined) {
      fail;
      return;
    }

    const requestVerified = verifyBlindSignRequest(
      commitment,
      pokForCommitment,
      challenge,
    );
    expect(requestVerified.verified).toBeTruthy();

    const blindedProof = blindSign(
      commitment,
      doc1,
      proofWithoutProofvalue1,
      keyGraph,
    );
    expect(blindedProof).toBeDefined();

    const proof = unblind(doc1, blindedProof, blinding);
    expect(proof).toBeDefined();

    const verified = blindVerify(secret, doc1, proof, keyGraph);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof with secret', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: boundProof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedBoundProof1,
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
      secret,
    };
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();

    const verified = verifyProof({ vp, keyGraph, challenge });
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof with domain and blind sign request', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const blindSignRequest = requestBlindSign(secret, undefined, true);
    expect(blindSignRequest.pokForCommitment).toBeUndefined();

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: boundProof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedBoundProof1,
    };
    const vcPair2: DeriveProofVcPair = {
      originalDocument: doc2,
      originalProof: proof2,
      disclosedDocument: disclosedDoc2,
      disclosedProof: disclosedProof2,
    };

    const challenge = 'abcde';
    const domain = 'example.org';

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1, vcPair2],
      deanonMap,
      keyGraph,
      challenge,
      domain,
      secret,
      blindSignRequest,
    };
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();

    const verified = verifyProof({ vp, keyGraph, challenge, domain });
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof with blind sign reqeust and PPID', async () => {
    await initializeWasm();

    const deanonMap = new Map([
      ['_:e0', '<did:example:john>'],
      ['_:e1', '<http://example.org/vaccine/a>'],
      ['_:e2', '<http://example.org/vcred/00>'],
      ['_:e3', '<http://example.org/vicred/a>'],
    ]);
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const blindSignRequest = requestBlindSign(secret, undefined, true);
    expect(blindSignRequest.pokForCommitment).toBeUndefined();

    const vcPair1: DeriveProofVcPair = {
      originalDocument: doc1,
      originalProof: boundProof1,
      disclosedDocument: disclosedDoc1,
      disclosedProof: disclosedBoundProof1,
    };
    const vcPair2: DeriveProofVcPair = {
      originalDocument: doc2,
      originalProof: proof2,
      disclosedDocument: disclosedDoc2,
      disclosedProof: disclosedProof2,
    };

    const challenge = 'abcde';
    const domain = 'example.org';

    const req: DeriveProofRequest = {
      vcPairs: [vcPair1, vcPair2],
      deanonMap,
      keyGraph,
      challenge,
      domain,
      secret,
      blindSignRequest,
      withPpid: true,
    };
    const vp = deriveProof(req);
    console.log(`vp: ${vp}`);

    expect(vp).toBeTruthy();

    const verified = verifyProof({ vp, keyGraph, challenge, domain });
    expect(verified.verified).toBeTruthy();
  });
});
