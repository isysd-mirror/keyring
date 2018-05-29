/* global describe:false it:false before:false */
const assert = require('chai').assert
const pgp = require('./keyring.js')
const fs = require('fs')
const pubkey = fs.readFileSync('fixtures/pubkey.asc', 'ascii').trim()
const privkey = fs.readFileSync('fixtures/privkey.asc', 'ascii').trim()
const fpr = 'cff501437e131fdb6c2ca2fd2bf7f4af45851864'
describe('PGPKeyring', function () {
  before(() => {
    pgp.clear()
  })
  //  it('generate', async () => {
  //    this.key = await pgp.generate({
  //      numBits: 4096,
  //      passphrase: 'password',
  //      userIds: [{
  //        name: 'testuser',
  //        email: 'testuser@guld.io'
  //      }]
  //    })
  //    assert.exists(this.key)
  //    assert.exists(this.key.primaryKey)
  //    assert.isTrue(this.key.primaryKey.isDecrypted)
  //  }).timeout(10000)
  it('importPublicKey', async () => {
    await pgp.importPublicKey(pubkey)
  })
  it('getPublicKey', async () => {
    this.pubkey = await pgp.getPublicKey(fpr)
    assert.equal(this.pubkey, pubkey)
  })
  it('listKeys', async () => {
    assert((await pgp.listKeys()).length === 1)
  })
  it('importPrivateKey', async () => {
    await pgp.importPrivateKey(privkey)
    this.privkey = await pgp.getPrivateKey(fpr)
    assert.equal(this.privkey, privkey)
  })
  it('isLocked', async () => {
    var islocked = await pgp.isLocked(fpr)
    assert.isTrue(islocked)
  })
  it('unlock', async () => {
    await pgp.unlockKey(fpr, 'password')
    var islocked = await pgp.isLocked(fpr)
    assert.exists(islocked)
    assert.isNotTrue(islocked)
  })
  it('lock', async () => {
    await pgp.lockKey(fpr, 'password')
    var islocked = await pgp.isLocked(fpr)
    assert.isTrue(islocked)
  })
  it('lock already locked', async () => {
    await pgp.lockKey(fpr, 'password')
    var islocked = await pgp.isLocked(fpr)
    assert.isTrue(islocked)
  })
  it('unlock already unlocked', async () => {
    await pgp.unlockKey(fpr, 'password')
    var islocked = await pgp.isLocked(fpr)
    assert.exists(islocked)
    assert.isNotTrue(islocked)
  })
  it('sign', async () => {
    this.sig = await pgp.sign('hello', fpr, 'password')
    assert.exists(this.sig)
    assert.equal(typeof this.sig, 'string')
  }).timeout(3000)
  it('verify bad signature', async () => {
    var verified = await pgp.verify('hell', this.sig, fpr)
    assert.exists(verified)
    assert.isFalse(verified)
  })
  it('verify good signature', async () => {
    var verified = await pgp.verify('hello', this.sig, fpr, 'password')
    assert.exists(verified)
    assert.isTrue(verified)
  })
  it('encrypt', async () => {
    this.ciphertext = await pgp.encrypt('hello', fpr, 'password')
    assert.exists(this.ciphertext)
    assert.equal(typeof this.ciphertext, 'string')
  }).timeout(3000)
  it('decrypt', async () => {
    var message = await pgp.decrypt(this.ciphertext, fpr, 'password')
    assert.exists(message)
    assert.equal(message, 'hello')
  })
})
