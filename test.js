/* global describe:false it:false before:false */
const assert = require('chai').assert
const gpg = require('./keyring.js')
const pify = require('pify')
const path = require('path')
const nfs = require('fs')
const fs = pify(nfs)
const pubkey = nfs.readFileSync('fixtures/pubkey.asc', 'ascii').trim()
const privkey = nfs.readFileSync('fixtures/privkey.asc', 'ascii').trim()
const fpr = 'B92828C1D851FF85EA643D10BD00ACBCA6123BCB'

describe('GPGKeyring', function () {
  before(async () => {
    await gpg.clear()
    await fs.writeFile(path.join(process.env.GNUPGHOME, 'gpg-agent.conf'), 'default-cache-ttl 3600\n')
  })
  after(async () => {
    await gpg.clear()
    await gpg.lockKey(fpr)
  })
  it('generate', async () => {
    this.fpr = await gpg.generate({
      passphrase: 'password',
      numBits: 1024,
      userIds: [{
        name: 'testu',
        email: 'testu@guld.io'
      }]
    })
    assert.exists(this.fpr)
    /*console.log(this.fpr)
    pubkey = (await gpg.getPublicKey(this.fpr)).trim()
    await fs.writeFile('fixtures/pubkey.asc')
    privkey = (await gpg.getPrivateKey(this.fpr)).trim()
    await fs.writeFile('fixtures/privkey.asc')*/
  }).timeout(10000)
  it('importPublicKey', async () => {
    await gpg.importPublicKey(pubkey)
    assert.isTrue(true)
  })
  it('getPublicKey', async () => {
    this.pubkey = await gpg.getPublicKey(fpr)
    assert.equal(this.pubkey.trim(), pubkey)
  })
  it('listKeys', async () => {
    assert((await gpg.listKeys()).length === 2)
  })
  it('importPrivateKey', async () => {
    await gpg.importPrivateKey(privkey, 'password')
    this.privkey = await gpg.getPrivateKey(fpr, 'password')
    assert.exists(this.privkey.match('-----BEGIN PGP PRIVATE KEY BLOCK-----'))
  }).timeout(10000)
  it('isLocked', async () => {
    var islocked = await gpg.isLocked(fpr)
    assert.isNotTrue(islocked)
  }).timeout(15000)
  /*it('lock', async () => {
    await gpg.lockKey(fpr, 'password')
    var islocked = await gpg.isLocked(fpr)
    assert.isTrue(islocked)
  })*/
  it('unlock', async () => {
    await gpg.unlockKey(fpr, 'password')
    var islocked = await gpg.isLocked(fpr)
    assert.exists(islocked)
    assert.isNotTrue(islocked)
  }).timeout(15000)
  it('sign', async () => {
    this.sig = await gpg.sign('hello', fpr)
    assert.exists(this.sig)
    assert.equal(typeof this.sig, 'string')
  }).timeout(3000)
  it('verify bad signature', async () => {
    var verified = await gpg.verify('hell', this.sig, fpr)
    assert.exists(verified)
    assert.isFalse(verified)
  })
  it('verify good signature', async () => {
    var verified = await gpg.verify('hello', this.sig, fpr)
    assert.exists(verified)
    assert.isTrue(verified)
  })
  it('encrypt', async () => {
    this.ciphertext = await gpg.encrypt('hello', fpr)
    assert.exists(this.ciphertext)
    assert.equal(typeof this.ciphertext, 'string')
  }).timeout(3000)
  it('decrypt', async () => {
    var message = await gpg.decrypt(this.ciphertext, fpr)
    assert.exists(message)
    assert.equal(message, 'hello')
  })
})
