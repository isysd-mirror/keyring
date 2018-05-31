const openpgp = require('openpgp')
const eol = require('eol')
let keyring = new openpgp.Keyring()

async function generate (options) {
  var key = await openpgp.generateKey(options)
  await this.importPublicKey(key.publicKeyArmored)
  await this.importPrivateKey(key.privateKeyArmored)
  this.store()
  await this.unlock(options.passphrase)
  return key
}

async function clear () {
  keyring.clear()
}

async function store () {
  keyring.store()
}

async function listKeys () {
  return keyring.publicKeys.keys.map(k => {
    return k.primaryKey.getFingerprint()
  })
}

async function importPublicKey (key) {
  await keyring.publicKeys.importKey(key)
  await this.store()
}

async function importPrivateKey (key) {
  await keyring.privateKeys.importKey(key)
  await this.store()
}

async function getPublicKey (fpr) {
  return eol.lf(keyring.publicKeys.getForId(fpr).armor()).trim()
}

async function getPrivateKey (fpr) {
  return eol.lf(keyring.privateKeys.getForId(fpr).armor()).trim()
}

async function isLocked (fpr) {
  return !keyring.privateKeys.getForId(fpr).primaryKey.isDecrypted
}

async function unlockKey (fpr, pass) {
  if (await this.isLocked(fpr)) return keyring.privateKeys.getForId(fpr).decrypt(pass)
}

async function lockKey (fpr, pass) {
  keyring = new openpgp.Keyring()
}

async function sign (message, fpr) {
  var signed = await openpgp.sign({
    data: message,
    privateKeys: [keyring.privateKeys.getForId(fpr)],
    detached: true
  })
  return signed.signature
}

async function verify (message, signature, signers) {
  if (typeof signers === 'string') signers = [signers]
  let options = {
    message: openpgp.message.fromText(message),
    signature: openpgp.signature.readArmored(signature),
    publicKeys: signers.map(s => {
      return keyring.publicKeys.getForId(s)
    })
  }
  let verified = await openpgp.verify(options)
  verified.signatures.forEach(v => {
    if (!v.valid) return
    var i = signers.indexOf(v.keyid.toHex())
    if (i >= 0) {
      signers = signers.splice(i, 1)
    } else {
      i = signers.indexOf(keyring.publicKeys.getForId(v.keyid.toHex()).primaryKey.getFingerprint())
      if (i >= 0) {
        signers.splice(i, 1)
      }
    }
  })
  return signers.length === 0
}

async function decrypt (message, fpr) {
  return (await openpgp.decrypt({
    message: openpgp.message.readArmored(message),
    privateKeys: [keyring.privateKeys.getForId(fpr)]
  })).data
}

async function encrypt (message, fpr) {
  return (await openpgp.encrypt({
    data: message,
    publicKeys: keyring.publicKeys.getForId(fpr),
    privateKeys: [keyring.privateKeys.getForId(fpr)]
  })).data
}

module.exports = {
  generate: generate,
  clear: clear,
  store: store,
  listKeys: listKeys,
  importPublicKey: importPublicKey,
  importPrivateKey: importPrivateKey,
  getPublicKey: getPublicKey,
  getPrivateKey: getPrivateKey,
  isLocked: isLocked,
  unlockKey: unlockKey,
  lockKey: lockKey,
  sign: sign,
  verify: verify,
  decrypt: decrypt,
  encrypt: encrypt
}
