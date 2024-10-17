import { initializeWasm, keyGen, ppidGen } from '../../lib';

describe('KeyGen', () => {
  test('keyGen', async () => {
    await initializeWasm();

    const keypair = keyGen();
    console.log(`keypair: ${JSON.stringify(keypair, null, 2)}`);

    expect(keypair).toBeDefined();
  });

  test('ppidGen', async () => {
    await initializeWasm();

    const secret = new Uint8Array(Buffer.from('SECRET'));
    const ppid1 = ppidGen(secret, 'domain1');
    const ppid2 = ppidGen(secret, 'domain2');
    const ppid3 = ppidGen(secret, 'domain3');

    expect(ppid1).toEqual(
      'did:key:z3tEF87ZHaidFGzwuDP5nKczSKzfhU5G9E41RMpWJmVgqVuXf5ULHQKTwaTrPCN8ASPxJ4',
    );
    expect(ppid2).toEqual(
      'did:key:z3tEGUU13oXvR5K5DhPzVzTcqzWi54fqdUV5m8QTcEsQ7a3QxQQevELHEtxjgaLJ8bBAZJ',
    );
    expect(ppid3).toEqual(
      'did:key:z3tEFKzuaPD7Z8iUmApcBtAaVE1UfRrrVxv1PuUAhsyCc2QYLiwMUAKg29tv6inXNZ15Nh',
    );
  });
});
