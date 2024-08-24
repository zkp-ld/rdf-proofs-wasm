import { initializeWasm, keyGen } from '../../lib';

describe('KeyGen', () => {
  test('keyGen', async () => {
    await initializeWasm();

    const keypair = keyGen();
    console.log(`keypair: ${JSON.stringify(keypair, null, 2)}`);

    expect(keypair).toBeDefined();
  });
});
