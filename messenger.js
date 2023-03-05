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
    const {pub, sec} = generateEG();
    /*
    store the ElGamal key pairs
    */
    this.EGKeyPair = {pub, sec};
    const certificate = {
      username, pub 
    };
    return certificate
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
    const {username, pub} = certificate;
    if (!verifyWithECDSA(this.caPublicKey, certString, signature)
    ){
      throw "Invalid Certificate";
    };
    /*
      store others' certificates
      */
      this.certs[username] = certificate
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
    
    /*
    obtain all the information needed
    */
    const senderCertificate = this.certs[name];
    const theirPublicKey = senderCertificate.pub;
    const {myPublicKey, myPrivateKey} = this.EGKeyPair;

    /*
    compute DH secret from sk and caPK 
    */
    const secret = computeDH(myPrivateKey, theirPublicKey);

    /* 
    check if name is in this.conn, if not initialize
    keep tracking root key (rk), chain key (ck)
    */
    if(!this.conns[name]){

      const {myPublicKeyNew, myPrivateKeyNew} = generateEG();
      const [rk, ck] = HKDF(secret, genRandomSalt(), "ratchet-str");
      this.conns[name] = {
        myPrivateKeyNew,
        theirPublicKey,
        rk, 
        ck
      };

    };
    
    let iv = genRandomSalt();
    const header = {myPublicKeyNew, iv}
    const ciphertext = encryptWithGCM(ck, plaintext, iv)
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
    throw ('not implemented!')
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
