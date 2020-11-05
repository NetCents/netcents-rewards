//@flow
const pbkdf2 = require('./pbkdf2');
const unorm = require('unorm');
const bip39 = require('bip39');
const base58 = require("bs58");
const { sha256, ripemd160 } = require('./hash');
const secp256k1 = require("secp256k1");

/**
* Creates instance of Mnemonic phrase
* @class Mnemonic
* @constructor
* @param {String} providedPhrase OPTIONAL phrase which will be used for seed
* @param {String} passphrase OPTIONAL passPhrase used for hashing
*/
module.exports = class Mnemonic {
  constructor(passphrase, providedPhrase) {
    this.phrase = providedPhrase || bip39.generateMnemonic();
    this.toAddress(passphrase);
  }

  /**
  * @param {String} passphrase OPTIONAL passphrase to sign phrase with
  * @param {String} network e.g. 'livenet'
  * @return {Class} returns Mnemonic with privateKey and address
  */
  toAddress(passphrase) {
    const seed = this._toSeed(passphrase);
    const privateKey = Buffer.from(sha256(seed), "hex");
    this.privateKey = privateKey.toString('hex');
    const publicKey = secp256k1.publicKeyCreate(privateKey, false);
    const sha256PublicKey = sha256(publicKey);
    const ripemdPublicKey = ripemd160(sha256PublicKey);
    const withVersionByte = Buffer.concat([Buffer.from('23886610', 'hex'), ripemdPublicKey]);
    const twiceSha256Result = sha256(sha256(withVersionByte));
    const checkSum = twiceSha256Result.slice(0, 4);
    const binaryAddress = Buffer.concat([withVersionByte, checkSum]);
    const encodedAddress = base58.encode(binaryAddress);
    this.address = encodedAddress;
    return this;
  }

  /**
  * Hash phrase
  * @private
  * @method _toSeed
  * @param {String} passphrase OPTIONAL passphrase to sign phrase with
  * @return {Hex} returns a hexadecimal representation of the phrase/string
  */
  _toSeed(passphrase) {
    passphrase = passphrase || '';
    return pbkdf2(unorm.nfkd(this.phrase), unorm.nfkd('mnemonic' + passphrase), 2048, 64);
  }
}
