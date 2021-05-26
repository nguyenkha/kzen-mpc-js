const assert = require('assert');
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');
const bindings = require('../native/index.node');

const CYPHER = 'aes-256-gcm';
const IV_LENGTH = 16;

function encrypt(key, data) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(CYPHER, key, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return {
    iv,
    tag: cipher.getAuthTag(),
    encrypted,
  };
}

function decrypt(key, data) {
  const decipher = createDecipheriv(CYPHER, key, data.iv);
  decipher.setAuthTag(data.tag);
  const decrypted = decipher.update(data.encrypted);
  return Buffer.concat([decrypted, decipher.final()]);
}

const Types = {
  GENERATE_ED25519_KEY: 1,
  SIGN_ED25519: 2,
  GENERATE_SECP256K1_KEY: 3,
  SIGN_SECP256K1: 4,
};

class Context {
  constructor(type, index, parties) {
    this.type = type;
    this.step = -1;
    this.isFinished = false;
    this.index = index;
    this.parties = parties;
  }

  static createGenerateEd25519Key(index, parties, threshold) {
    return new GenerateEd25519KeyContext(index, parties, threshold);
  }

  static createSignEd25519(share, parties, message) {
    return new SignEd25519Context(share, parties, message);
  }

  static createGenerateSecp256k1Key(index, parties, threshold) {
    return new GenerateSecp256k1KeyContext(index, parties, threshold);
  }

  static createSignSecp256k1(share, parties, message) {
    return new SignSecp256k1Context(share, parties, message);
  }

  process(message) {
    assert(!this.isFinished);
    let result;
    if (!message) {
      result = this.onResult();
    } else {
      assert(this.step === message.step, 'Invalid message step');
      this.results.push(message);
      // Enough message, process result
      if (this.results.length === this.parties.length) {
        // Sort result by parties index
        this.results.sort((a, b) => this.parties.indexOf(a.index) - this.parties.indexOf(b.index));
        result = this.onResult();
      }
    }
    if (result) {
      // Move to next step
      this.step++;
      result.step = this.step;
      result.index = this.index;
      // Store self message
      this.results = [result];
      return result;
    }
  }
}

class GenerateEd25519KeyContext extends Context {
  constructor(index, parties, threshold) {
    super(Types.GENERATE_ED25519_KEY, index, parties);
    this.threshold = threshold;
    this.params = {
      share_count: this.parties.length,
      threshold,
    };
  }

  onResult() {
    let result;
    if (!this.results) {
      // First step
      this.key = bindings.ed25519_create_key(this.index);
      const [bc1, blind] = bindings.ed25519_phase1_broadcast(this.key);
      result = {
        // Protocol
        blind,
        y: this.key.y_i,
        bc1,
      };
    } else {
      switch (this.step) {
        case 0: {
          const blinds = this.results.map(r => r.blind);
          const bc1s = this.results.map(r => r.bc1);
          this.ys = this.results.map(r => r.y);
          const { Err, Ok } = bindings.ed25519_phase1_verify_com_phase2_distribute(this.key, this.params, blinds, this.ys, bc1s, this.parties);
          if (Err) {
            throw Error(Err);
          }
          const [vssScheme, secretShare] = Ok;
          // Prepare encrypt key
          this.encryptionKeys = this.parties.map((p, i) => {
            // Use this private key
            if (p === this.index) {
              return this.key.u_i;
            }
            // PK2 * SK1 * G = PK1 * SK2 * G
            return bindings.ed25519_mul(this.ys[i], this.key.u_i);
          }).map(k => Buffer.from(k.padStart(64, 0), 'hex'));
          result = {
            vssScheme,
            secretShare: secretShare.map((s, i) => encrypt(this.encryptionKeys[i], Buffer.from(s.padStart(64, 0), 'hex'))),
          };
          break;
        }
        case 1: {
          this.vssSchemes = this.results.map(r => r.vssScheme);
          this.partyShares = this.results
            .map(r => r.secretShare[this.parties.indexOf(this.index)])
            .map((e, i) => decrypt(this.encryptionKeys[i], e).toString('hex'));
          const { Err, Ok } = bindings.ed25519_phase2_verify_vss_construct_keypair(this.key, this.params, this.ys, this.partyShares, this.vssSchemes);
          if (Err) {
            throw Error(Err);
          }
          this.isFinished = true;
          this.sharedKey = Ok;
          break;
        }
      }
    }
    return result;
  }

  getShare() {
    assert(this.isFinished, 'The context is unfinished');
    return {
      index: this.index,
      parties: this.parties,
      key: this.key,
      sharedKey: this.sharedKey,
      vssSchemes: this.vssSchemes,
      ys: this.ys,
      encryptionKeys: this.encryptionKeys,
    };
  }

  getPublicKey() {
    assert(this.isFinished, 'The context is unfinished');
    return Buffer.from(this.sharedKey.y.padStart(64, '0'), 'hex');
  }
}

class SignEd25519Context extends Context {
  // Parties is signers
  constructor(share, parties, message) {
    super(Types.SIGN_ED25519, share.index, parties);
    this.share = share;
    // Convert to array of number
    this.message = [...message];
    this.key = share.key;
    this.params = {
      threshold: share.vssSchemes[0].parameters.threshold,
      share_count: parties.length,
    };
  }

  onResult() {
    let result;
    if (!this.results) {
      this.ephKey = bindings.ed25519_create_ephermeral_key(this.key, this.message);
      const [bc1, blind] = bindings.ed25519_ephermeral_phase1_broadcast(this.ephKey);
      result = {
        // Protocol
        blind,
        R: this.ephKey.R_i,
        bc1,
      };
    } else {
      switch (this.step) {
        case 0: {
          this.blinds = this.results.map(r => r.blind);
          this.Rs = this.results.map(r => r.R);
          this.bc1s = this.results.map(r => r.bc1);
          const { Err, Ok } = bindings.ed25519_ephermeral_phase1_verify_com_phase2_distribute(this.ephKey, this.params, this.blinds, this.Rs, this.bc1s, this.parties);
          if (Err) {
            throw Error(Err);
          }
          const [vssScheme, secretShare] = Ok;
          result = {
            vssScheme,
            secretShare: secretShare.map((s, i) => encrypt(this.share.encryptionKeys[this.share.parties.indexOf(this.parties[i])], Buffer.from(s.padStart(64, 0), 'hex'))),
          };
          break;
        }
        case 1: {
          this.vssSchemes = this.results.map(r => r.vssScheme);
          // TODO: Decrypte secret share
          this.partyShares = this.results
            .map(r => r.secretShare[this.parties.indexOf(this.index)])
            .map((e, i) => decrypt(this.share.encryptionKeys[this.share.parties.indexOf(this.parties[i])], e).toString('hex'));
          const { Err, Ok } = bindings.ed25519_ephermeral_phase2_verify_vss_construct_keypair(this.ephKey, this.params, this.Rs, this.partyShares, this.vssSchemes, this.index);
          if (Err) {
            throw Error(Err);
          }
          this.ephSharedKey = Ok;
          const localSig = bindings.ed25519_compute_local_sig(this.message, this.ephSharedKey, this.share.sharedKey);
          result = {
            localSig,
          };
          break;
        }
        case 2: {
          const indcies = this.parties.map(i => i - 1);
          const localSigs = this.results.map(r => r.localSig);
          const { Err, Ok } = bindings.ed25519_verify_local_sig(localSigs, indcies, this.share.vssSchemes, this.vssSchemes);
          if (Err) {
            throw Error(Err);
          }
          const sum = Ok;
          this.signature = bindings.ed25519_generate_signature(sum, localSigs, indcies, this.ephSharedKey.R);
          this.isFinished = true;
          break;
        }
      }
    }
    return result;
  }

  getSignature() {
    assert(this.isFinished, 'The context is unfinished');
    return Buffer.concat([
      Buffer.from(this.signature.R.padStart(64, '0'), 'hex'),
      // reverse sigma to LE
      Buffer.from(this.signature.sigma.padStart(64, '0'), 'hex').reverse(),
    ]);
  }
}

class GenerateSecp256k1KeyContext extends Context {
  constructor(index, parties, threshold) {
    super(Types.GENERATE_SECP256K1_KEY, index, parties);
    this.threshold = threshold;
    this.params = {
      share_count: this.parties.length,
      threshold,
    };
  }

  onResult() {
    let result;
    if (!this.results) {
      this.stage1Result = bindings.secp256k1_keygen_stage1({
        index: this.parties.indexOf(this.index),
      });
      result = {
        bc1: this.stage1Result.bc_com1_l,
        dc1: this.stage1Result.decom1_l,
      };
    } else {
      switch (this.step) {
        case 0: {
          this.bc1s = this.results.map(r => r.bc1);
          const dc1s = this.results.map(r => r.dc1);
          this.ys = dc1s.map(d => d.y_i);
          const { Err, Ok } = bindings.secp256k1_keygen_stage2({
            index: this.parties.indexOf(this.index),
            params_s: this.params,
            party_keys_s: this.stage1Result.party_keys_l,
            decom1_vec_s: dc1s,
            bc1_vec_s: this.bc1s,
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage2Result = Ok;
          const vssScheme = this.stage2Result.vss_scheme_s;
          const secretShare = this.stage2Result.secret_shares_s;
          // Prepare encrypt key
          this.encryptionKeys = this.parties.map((p, i) => {
            // Use this private key
            if (p === this.index) {
              return this.stage1Result.party_keys_l.u_i;
            }
            // PK2 * SK1 * G = PK1 * SK2 * G
            return bindings.secp256k1_mul(this.ys[i], this.stage1Result.party_keys_l.u_i).x;
          }).map(k => Buffer.from(k.padStart(64, 0), 'hex'));
          result = {
            vssScheme,
            secretShare: secretShare.map((s, i) => encrypt(this.encryptionKeys[i], Buffer.from(s.padStart(64, 0), 'hex'))),
          };
          break;
        }
        case 1: {
          this.vssSchemes = this.results.map(r => r.vssScheme);
          // TODO: Decrypte secret share
          const partyShares = this.results
            .map(r => r.secretShare[this.parties.indexOf(this.index)])
            .map((e, i) => decrypt(this.encryptionKeys[i], e).toString('hex'));;
          const { Err, Ok } = bindings.secp256k1_keygen_stage3({
            party_keys_s: this.stage1Result.party_keys_l,
            vss_scheme_vec_s: this.vssSchemes,
            secret_shares_vec_s: partyShares,
            y_vec_s: this.ys,
            index_s: this.parties.indexOf(this.index),
            params_s: this.params,
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage3Result = Ok;
          result = {
            dlogProof: this.stage3Result.dlog_proof_s,
          };
          break;
        }
        case 2: {
          const dlogProofs = this.results.map(r => r.dlogProof);
          const { Err } = bindings.secp256k1_keygen_stage4({
            dlog_proof_vec_s: dlogProofs,
            y_vec_s: this.ys,
            params_s: this.params,
          });
          if (Err) {
            throw Error(Err);
          }
          this.isFinished = true;
          break;
        }
      }
    }
    return result;
  }

  getShare() {
    assert(this.isFinished, 'The context is unfinished')
    return {
      paillierKeys: this.bc1s.map(b => b.e),
      h1h2NTildes: this.bc1s.map(b => b.dlog_statement),
      key: this.stage1Result.party_keys_l,
      sharedKey: this.stage3Result.shared_keys_s,
      index: this.index,
      parties: this.parties,
      vssSchemes: this.vssSchemes,
      encryptionKeys: this.encryptionKeys,
    };
  }

  getPublicKey() {
    return this.stage3Result.shared_keys_s.y;
  }
}

class SignSecp256k1Context extends Context {
  constructor(share, parties, message) {
    super(Types.SIGN_SECP256K1, share.index, parties);
    this.share = share;
    // Convert to array of number
    this.message = [...message];
    this.key = share.key;
  }

  onResult() {
    let result;
    if (!this.results) {
      this.stage1Result = bindings.secp256k1_sign_stage1({
        vss_scheme: this.share.vssSchemes[this.share.parties.indexOf(this.index)],
        // Index in whole group
        index: this.share.parties.indexOf(this.index),
        s_l: this.parties.map(i => this.share.parties.indexOf(i)),
        party_keys: this.key,
        shared_keys: this.share.sharedKey,
      });
      result = {
        bc1: this.stage1Result.bc1,
        ma: this.stage1Result.m_a[0],
        gwi: this.stage1Result.sign_keys.g_w_i,
      };
    } else {
      switch (this.step) {
        case 0: {
          this.bc1s = this.results.map(r => r.bc1);
          this.gwis = this.results.map(r => r.gwi);
          const mas = this.results.map(r => r.ma);
          const { Err, Ok } = bindings.secp256k1_sign_stage2({
            m_a_vec: mas,
            gamma_i: this.stage1Result.sign_keys.gamma_i,
            w_i: this.stage1Result.sign_keys.w_i,
            ek_vec: this.share.paillierKeys,
            // Index in signers group
            index: this.parties.indexOf(this.index),
            l_ttag: this.parties.length,
            l_s: this.parties.map(i => this.share.parties.indexOf(i)),
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage2Result = Ok;
          result = {
            mbgi: this.parties.map((p, i) => p === this.index ? null : encrypt(this.share.encryptionKeys[this.share.parties.indexOf(p)], Buffer.from(JSON.stringify(this.stage2Result.gamma_i_vec[i > this.parties.indexOf(this.index) ? i - 1 : i][0])))),
            mbwi: this.parties.map((p, i) => p === this.index ? null : encrypt(this.share.encryptionKeys[this.share.parties.indexOf(p)], Buffer.from(JSON.stringify(this.stage2Result.w_i_vec[i > this.parties.indexOf(this.index) ? i - 1 : i][0])))),
          };
          break;
        }
        case 1: {
          this.mbgis = this.results.map((r, i) => r.mbgi[this.parties.indexOf(this.index)] ? JSON.parse(decrypt(this.share.encryptionKeys[this.share.parties.indexOf(this.parties[i])], r.mbgi[this.parties.indexOf(this.index)])) : null).filter(m => m);
          const mbwis = this.results.map((r, i) => r.mbwi[this.parties.indexOf(this.index)] ? JSON.parse(decrypt(this.share.encryptionKeys[this.share.parties.indexOf(this.parties[i])], r.mbwi[this.parties.indexOf(this.index)])) : null).filter(m => m);
          let { Err, Ok } = bindings.secp256k1_sign_stage3({
            dk_s: this.key.dk,
            k_i_s: this.stage1Result.sign_keys.k_i,
            m_b_gamma_s: this.mbgis,
            m_b_w_s: mbwis,
            index_s: this.parties.indexOf(this.index),
            ttag_s: this.parties.length,
            g_w_i_s: this.gwis,
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage3Result = Ok;   
          ({ Err, Ok } = bindings.secp256k1_sign_stage4({
            alpha_vec_s: this.stage3Result.alpha_vec_gamma,
            miu_vec_s: this.stage3Result.alpha_vec_w,
            beta_vec_s: this.stage2Result.gamma_i_vec.map(g => g[1]),
            ni_vec_s: this.stage2Result.w_i_vec.map(w => w[1]),
            sign_keys_s: this.stage1Result.sign_keys,
          }));
          if (Err) {
            throw Error(Err);
          }
          this.stage4Result = Ok;
          result = {
            dc1: this.stage1Result.decom1,
            delta: this.stage4Result.delta_i,
          };
          break;
        }
        case 2: {
          const dc1s = this.results.map(r => r.dc1);
          const deltas = this.results.map(r => r.delta);
          const deltaInvert = bindings.secp256k1_phase3_reconstruct_delta(deltas);
          const { Err, Ok } = bindings.secp256k1_sign_stage5({
            m_b_gamma_vec: this.mbgis,
            delta_inv: deltaInvert,
            decom_vec1: dc1s,
            bc1_vec: this.bc1s,
            index: this.parties.indexOf(this.index),
            sign_keys: this.stage1Result.sign_keys,
            s_ttag: this.parties.length,
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage5Result = Ok;
          result = {
            r: this.stage5Result.R,
            rDash: this.stage5Result.R_dash,
          };
          break;
        }
        case 3: {
          const rDashs = this.results.map(r => r.rDash);
          const { Err, Ok } = bindings.secp256k1_sign_stage6({
            R_dash_vec: rDashs,
            R: this.stage5Result.R,
            m_a: this.stage1Result.m_a[0],
            randomness: this.stage1Result.m_a[1],
            e_k: this.share.paillierKeys[this.share.parties.indexOf(this.index)],
            k_i: this.stage1Result.sign_keys.k_i,
            party_keys: this.key,
            h1_h2_N_tilde_vec: this.share.h1h2NTildes,
            index: this.parties.indexOf(this.index),
            s: this.parties.map(i => this.share.parties.indexOf(i)),
            sigma: this.stage4Result.sigma_i,
            ysum: this.share.sharedKey.y,
            sign_key: this.stage1Result.sign_keys,
            message_bn: bindings.to_big_int(this.message),
          });
          if (Err) {
            throw Error(Err);
          }
          this.stage6Result = Ok;
          result = {
            localSig: this.stage6Result.local_sig,
          };
          break;
        }
        case 4: {
          const localSigs = this.results.map(r => r.localSig);
          const { Err, Ok } = bindings.secp256k1_sign_stage7({
            local_sig_vec: localSigs,
            ysum: this.share.sharedKey.y,
          });
          if (Err) {
            throw Error(Err);
          }
          this.signature = Ok.local_sig;
          // Verify
          // console.log(bindings.secp256k1_verify_signature(this.signature, this.share.sharedKey.y, bindings.hash_bytes_to_big_int(this.message)));
          this.isFinished = true;
          break;
        }
      }
    }
    return result;
  }

  getSignature() {
    assert(this.isFinished, 'The context is unfinished');
    return this.signature;
  }
}

module.exports = Context;
