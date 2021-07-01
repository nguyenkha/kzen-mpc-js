const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const { createHash } = require('crypto');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const Context = require('../lib/context');
const bindings = require('../native/index.node');

console.log('Generating...');
const parties = [...Array(15).keys()].map(i => i + 1);
const threshold = 4;
const contexts = parties.map(i => Context.createGenerateSecp256k1Key(i, parties, threshold));
let results;
results = contexts.map(c => c.process());
results = contexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = contexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = contexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
const shares = contexts.map(c => c.getShare());
const publicKey = ec.keyFromPublic(contexts[0].getPublicKey());
console.log('Public key:', publicKey.validate().result);
console.log('Hex:', publicKey.getPublic(true, 'hex'));

const constructIndices = [0, 1, 2, 3, 4];
const constructShares = shares.filter((_, i) => constructIndices.includes(i));
const vss = constructShares[0].vssSchemes[0];
const xs = constructShares.map(s => s.sharedKey.x_i);
const privateKey = ec.keyFromPrivate(bindings.secp256k1_construct_private(vss, constructIndices, xs));
console.log('From private key:', privateKey.getPublic(true, 'hex'));

console.log('Signing...');
const message = createHash('SHA256').update(Buffer.from('Hello world')).digest();
const signParties = [2, 5, 7, 3, 9];
const signContexts = shares
  .filter((s) => signParties.includes(s.index))
  .map(s => Context.createSignSecp256k1(s, signParties, message));
results = signContexts.map(c => c.process());
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
results = signContexts.map(c => results.filter(r => r.index !== c.index).map(r => c.process(r)).find(r => r));
const signature = signContexts[0].getSignature();
const s = new Signature({
  r: signature.r,
  s: signature.s,
  recoveryParam: signature.recid,
});
console.log('Verify signature:', publicKey.verify(message, s));