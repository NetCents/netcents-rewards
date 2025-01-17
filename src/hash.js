'use strict';

var crypto = require('crypto');

var Hash = module.exports;

Hash.sha1 = function (buf) {
  return crypto.createHash('sha1').update(buf).digest();
};

Hash.sha1.blocksize = 512;

Hash.sha256 = function (buf) {
  return crypto.createHash('sha256').update(buf).digest();
};

Hash.sha256.blocksize = 512;

Hash.sha256sha256 = function (buf) {
  return Hash.sha256(Hash.sha256(buf));
};

Hash.sha256x2 = function (buffer) {
  return sha256(Buffer.from(sha256(buffer), 'hex'))
}

Hash.ripemd160 = function (buf) {
  return crypto.createHash('ripemd160').update(buf).digest();
};

Hash.sha256ripemd160 = function (buf) {
  return Hash.ripemd160(Hash.sha256(buf));
};

Hash.sha256x2 = function (hex) {
  return Hash.sha256(Hash.sha256(Buffer.from(hex, 'hex')))
}
Hash.sha512 = function (buf) {
  return crypto.createHash('sha512').update(buf).digest();
};

Hash.sha512.blocksize = 1024;

Hash.hmac = function (hashf, data, key) {
  var blocksize = hashf.blocksize / 8;

  if (key.length > blocksize) {
    key = hashf(key);
  } else if (key < blocksize) {
    var fill = new Buffer(blocksize);
    fill.fill(0);
    key.copy(fill);
    key = fill;
  }

  var o_key = new Buffer(blocksize);
  o_key.fill(0x5c);

  var i_key = new Buffer(blocksize);
  i_key.fill(0x36);

  var o_key_pad = new Buffer(blocksize);
  var i_key_pad = new Buffer(blocksize);
  for (var i = 0; i < blocksize; i++) {
    o_key_pad[i] = o_key[i] ^ key[i];
    i_key_pad[i] = i_key[i] ^ key[i];
  }

  return hashf(Buffer.concat([o_key_pad, hashf(Buffer.concat([i_key_pad, data]))]));
};

Hash.sha256hmac = function (data, key) {
  return Hash.hmac(Hash.sha256, data, key);
};

Hash.sha512hmac = function (data, key) {
  return Hash.hmac(Hash.sha512, data, key);
};
