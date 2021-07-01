const Context = require('../lib/context');
const nacl = require('tweetnacl');
const bindings = require('../native/index.node');

console.log('Generating...');
const parties = [...Array(15).keys()].map(i => i + 1);
const threshold = 4;
const contexts = parties.map(i => Context.createGenerateEd25519Key(i, parties, threshold));
let results;
results = contexts.map(c => c.process());
results = contexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = contexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
const shares = contexts.map(c => c.getShare());
const publicKey = contexts[0].getPublicKey();
console.log('Public key:', shares[0].sharedKey.y);

const constructIndices = [0, 1, 2, 3, 4];
const constructShares = shares.filter((_, i) => constructIndices.includes(i));
const vss = constructShares[0].vssSchemes[0];
const xs = constructShares.map(s => s.sharedKey.x_i);
const privateKey = bindings.ed25519_construct_private(vss, constructIndices, xs);
console.log('Private key:', privateKey);
const publicKey2 = bindings.ed25519_to_public_key(privateKey);
console.log('Public key from private key:', publicKey2);

console.log('Signing...');
const message = Buffer.from('Hello world');
const signParties = [2, 5, 7, 3, 9];
const signContexts = shares
  .filter((s) => signParties.includes(s.index))
  .map(s => Context.createSignEd25519(s, signParties, message));
results = signContexts.map(c => c.process());
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r))
const signature = signContexts[0].getSignature();
console.log('Verified signature:', nacl.sign.detached.verify(message, signature, publicKey));
