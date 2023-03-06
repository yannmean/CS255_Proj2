
'use strict'
/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

/* Write out all the functions following the Signal protocol */

async function KDF_RK(rk, dh_out){
  return await HKDF(rk, dh_out, "ratchet-str")
}

async function KDF_CK(ck){
  let ckNew = await HMACtoHMACKey(ck, "chainKey");
  let mk = await HMACtoAESKey(ck, "messageKey");
  let mkBuf = await HMACtoAESKey(ck, "messageKey", true);
  return [ckNew, mk, mkBuf]
}

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey

    /*
    perhaps for each active connection, for each name, we can save 
    the DH secret, 
    */
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG();
    const certificate = {
      username: username,
      publicKeyJSON: await cryptoKeyToJSON(this.EGKeyPair.pub),
      publicKey: this.EGKeyPair.pub
    };
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    const verification = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!verification && await cryptoKeyToJSON(certificate.publicKey) != certificate.publicKeyJSON) {
      throw ("Certificate is not valid!");
    }

    this.certs[certificate.username] = certificate;
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    if (!(name in this.conns)) { 
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);

      const dhs = await generateEG();
      const dhsOutput = await computeDH(dhs.sec, this.certs[name].publicKey);

      const [rk, cks] = await KDF_RK(initialRootKey, dhsOutput);

      this.conns[name] = {
        DHs: dhs,
        DHr: this.certs[name].publicKey,
        RK: rk,
        CKs: cks,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}, 
      };
    }

    const connection = this.conns[name];
    if (connection.CKs === null) {
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);

      const dhs = await generateEG();
      const dhsOutput = await computeDH(dhs.sec, this.certs[name].publicKey);

      const [rk, cks] = await KDF_RK(initialRootKey, dhsOutput);
      connection.RK = rk;
      connection.DHs = dhs;
      connection.CKs = cks;
    }
    const [CKs, mk, mkBuf] = await KDF_CK(connection.CKs);
    connection.CKs = CKs;

    const iv = genRandomSalt();

    const ivGov = genRandomSalt();
    const dhGov = await generateEG();

    const sharedGovKey = await computeDH(dhGov.sec, this.govPublicKey);
    const aesKeyGov = await HMACtoAESKey(sharedGovKey, govEncryptionDataStr);
    const cGov = await encryptWithGCM(aesKeyGov, mkBuf, ivGov)

    const header = {
      DHs: connection.DHs,
      PN: connection.PN,
      Ns: connection.Ns,
      receiverIV: iv,
      vGov: dhGov.pub,
      cGov: cGov,
      ivGov: ivGov,
    }
    connection.Ns += 1;

    const ciphertext = await encryptWithGCM(mk, plaintext, iv, JSON.stringify(header));
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    if (!(name in this.conns)) { 
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);
      const dhOutputOne = await computeDH(this.EGKeyPair.sec, header.DHs.pub);
      const [rk, ckr] = await KDF_RK(initialRootKey, dhOutputOne);

      this.conns[name] = {
        DHs: this.EGKeyPair, //sending key
        DHr: header.DHs.pub,           //receiving key
        RK: initialRootKey,  //root key
        CKs: null,           //chaining sending key
        CKr: ckr,           //receiving sending key
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}, 
      };

    }
    const connection = this.conns[name];
    if (connection.CKr === null) {
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);
      const dhOutputOne = await computeDH(this.EGKeyPair.sec, header.DHs.pub);
      const [rk, ckr] = await KDF_RK(initialRootKey, dhOutputOne);
      connection.RK = rk;
      connection.CKr = ckr;
    }
    const [CKr, mk, _] = await KDF_CK(connection.CKr);
    connection.CKr = CKr;
    connection.Nr += 1;
    // const connection = this.conns[name];
    // const newConnection = {...connection};

    // newConnection.Nr += 1;

    // newConnection.DHs = await generateEG();

    // const dhOutputTwo = await computeDH(newConnection.DHs.sec, newConnection.DHr);
    // const newSendingKeys = await KDF_RK(newConnection.RK, dhOutputTwo);
    // newConnection.RK = newSendingKeys[0];
    // newConnection.CKs = newSendingKeys[1];
    // const [CKr, mk, _] = await KDF_CK(newConnection.CKr);
    // newConnection.CKr = CKr;
    try {
      const plaintext = byteArrayToString(await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header)));
      return plaintext;
    } catch (err) {
      throw ("Message integrity comprimized");
    }
  }
};

module.exports = {
  MessengerClient
}
