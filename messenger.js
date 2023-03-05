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

function GENDERATE_DH(){
  return generateEG()
}

function DH(dh_pair, dh_pub){
  return computeDH(dh_pair.sec, dh_pub)
}

function KDF_RK(rk, dh_out){
  return HKDF(rk, genRandomSalt(), "ratchet-str")
}

function KDF_CK(ck){
  let ckNew = HMACtoHMACKey(ck, "chainKey");
  let mk = HMACtoAESKey(ck, "messageKey");
  return [ckNew, mk]
}

function ENCRYPT(mk, plaintext, iv, associated_data){
  return encryptWithGCM(mk, plaintext, iv, associated_data)
}

function DECRYPT(mk, ciphertext, iv, associated_data){
  return decryptWithGCM(mk, ciphertext, iv, associated_data)
}

function HEADER(dh_pair, pn, n, mk, iv, govPublicKey){
  const dhGov = generateEG();
  const secret = DH(dhGov, govPublicKey);
  const aesKeyGov = HMACtoAESKey(secret, govEncryptionDataStr);
  const cGov = encryptWithGCM(aesKeyGov, mk, );
  const ivGov = genRandomSalt()
  return {
    pub: dh_pair.pub,
    previousChainLen: pn,
    messageNumber: n,
    vGov: dhGov.pub,
    cGov: cGov,
    ivGov: ivGov,
    iv: iv
  }
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
    const {pub, sec} = GENDERATE_DH();
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
    /* 
    See if H(pk, message) is equal to the signature or not
    Here pk is this.caPublicKey, message is certString
    */ 
    if (!(await verifyWithECDSA(this.caPublicKey, certString, signature))
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
    obtain receiver's certificat,
    from their cerficate, obtain their public key
    */
    const theirCertificate = this.certs[name]; 
    const theirPublicKey = theirCertificate.pub;

    //compute DH secret from sk and caPK 
    const secret = DH(this.EGKeyPair, theirPublicKey);
    
    /* 
    check if name is in this.conn, if not initialize
    keep tracking root key (rk), chain key (ck)
    */
    if(!this.conns[name]){

      const dhs = GENDERATE_DH();
      let dhr = theirPublicKey;
      let rk, cks = KDF_RK(secret, DH(dhs, dhr));
      this.conns[name] = {
        dhs,
        dhr,
        rk,
        cks, 
        ckr: null,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: {}
      };
    }; 
    
    const {ckNew, mk} = KDF_CK(this.conns[name].cks);
    this.conns[name].cks = ckNew;
    this.conns[name].ns++;
  
   
    /*
    create the header
    */
    const iv = genRandomSalt();
    const header = HEADER(
      this.conns[name].dhs, 
      this.conns[name].pn, 
      this.conns[name].n,
      mk,
      iv,
      this.govPublicKey
      )

    
    const ciphertext = ENCRYPT(mk, plaintext, iv, JSON.stringify(header));
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
