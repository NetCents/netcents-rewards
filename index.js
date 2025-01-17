const Mnemonic = require('./src/mnemonic');

module.exports = {
  // Generates a new wallet when no providedPhrase
  deriveWallet: (passphrase = null, providedPhrase = null) => {
    return new Mnemonic(passphrase, providedPhrase);
  }
};