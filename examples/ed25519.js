const Context = require('../lib/context');
const nacl = require('tweetnacl');

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

const signParties2 = [10, 11, 12, 13, 14, 15];
const signContexts2 = shares
  .filter((s) => signParties2.includes(s.index))
  .map(s => Context.createSignEd25519(s, signParties2, message));
results = signContexts2.map(c => c.process());
results = signContexts2.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts2.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts2.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r))
const signature2 = signContexts2[0].getSignature();
console.log('Verified signature:', nacl.sign.detached.verify(message, signature2, publicKey));