const Context = require('../lib/context');
const nacl = require('tweetnacl');
const EdDSA = require('elliptic').eddsa;
const ed25519 = new EdDSA('ed25519');
const KeyPair = require('elliptic/lib/elliptic/eddsa/key');
const { randomBytes } = require('crypto');
const bindings = require('../native/index.node');

// Stub key pair
class StubKeyPair extends KeyPair {
  constructor(privBytes) {
    // Stub
    super(ed25519, { secret: randomBytes(32) });
    this._secret = privBytes;
  }

  // Override
  privBytes() {
    return this._secret;
  }

  messagePrefix() {
    return randomBytes(32);
  }

  static fromPrivBytes(privBytes) {
    return new StubKeyPair(privBytes);
  }
}

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
const privateScalar = bindings.ed25519_construct_private(vss, constructIndices, xs);
console.log('Private scalar:', privateScalar);
const publicKey2 = bindings.ed25519_to_public_key(privateScalar);
console.log('Public key from private scalar:', publicKey2);

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
console.log('Signature:', signature.toString('hex'));
console.log('Verified signature:', nacl.sign.detached.verify(message, signature, publicKey));

// Reverse to LE
const keyPair = new StubKeyPair(Buffer.from(privateScalar.padStart(64, 0), 'hex').reverse());
const signature2 = Buffer.from(keyPair.sign(message).toBytes());
console.log('Verified signature from private key:', nacl.sign.detached.verify(message, signature2, publicKey));
