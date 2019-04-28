/* global openpgp:false */

const eol = require('eol')
let keyring = new openpgp.Keyring()
let loading = true

async function load () {
  if (loading) {
    await keyring.load()
    loading = false
  }
}

async function generate (options) {
  await load()
  var key = await openpgp.generateKey(options)
  var fpr = await importPrivateKey(key.privateKeyArmored)
  await unlockKey(fpr, options.passphrase)
  return fpr
}

async function clear () {
  await load()
  keyring.clear()
  await load()
}

async function store () {
  await load()
  await keyring.store()
}

async function listKeys () {
  await load()
  return keyring.publicKeys.keys.map(k => {
    return k.primaryKey.getFingerprint()
  })
}

async function importPublicKey (key) {
  await load()
  await keyring.publicKeys.importKey(key)
  await store()
  return (await openpgp.key.readArmored(key)).keys[0].primaryKey.getFingerprint()
}

async function importPrivateKey (key) {
  await load()
  await keyring.privateKeys.importKey(key)
  var fpr = (await openpgp.key.readArmored(key)).keys[0].primaryKey.getFingerprint()
  return importPublicKey(keyring.privateKeys.getForId(fpr).toPublic().armor())
}

async function getPublicKey (fpr) {
  await load()
  return eol.lf(keyring.publicKeys.getForId(fpr).armor()).trim()
}

async function getPrivateKey (fpr) {
  await load()
  return eol.lf(keyring.privateKeys.getForId(fpr).armor()).trim()
}

async function isLocked (fpr) {
  await load()
  return keyring.privateKeys.getForId(fpr).primaryKey.isEncrypted
}

async function unlockKey (fpr, pass) {
  await keyring.load()
  if (await isLocked(fpr)) {
    var resp = await keyring.privateKeys.getForId(fpr).decrypt(pass)
    return resp
  }
}

async function lockKey (fpr, pass) {
  await load()
  keyring = new openpgp.Keyring()
  loading = true
  await load()
}

async function sign (message, fpr, detached = true) {
  await load()
  var signed = await openpgp.sign({
    message: openpgp.message.fromText(message),
    privateKeys: [keyring.privateKeys.getForId(fpr)],
    detached: detached
  })
  return signed.signature
}

async function verify (message, signature, signers) {
  await load()
  if (typeof signers === 'string') signers = [signers]
  signers = signers.map(s => s.toUpperCase())
  let options
  if (signature) {
    options = {
      message: openpgp.message.fromText(message),
      signature: await openpgp.signature.readArmored(signature),
      publicKeys: signers.map(s => {
        return keyring.publicKeys.getForId(s.toLowerCase())
      })
    }
  } else {
    options = {
      message: await openpgp.cleartext.readArmored(message),
      publicKeys: signers.map(s => {
        return keyring.publicKeys.getForId(s.toLowerCase())
      })
    }
  }
  let verified = await openpgp.verify(options)
  verified.signatures.forEach(v => {
    if (!v.valid) return
    var i = signers.indexOf(v.keyid.toHex().toUpperCase())
    if (i >= 0) {
      signers = signers.splice(i, 1)
    } else {
      i = signers.indexOf(keyring.publicKeys.getForId(v.keyid.toHex()).primaryKey.getFingerprint().toUpperCase())
      if (i >= 0) {
        signers.splice(i, 1)
      }
    }
  })
  return signers.length === 0
}

async function decrypt (message, fpr) {
  await load()
  return (await openpgp.decrypt({
    message: await openpgp.message.readArmored(message),
    privateKeys: [keyring.privateKeys.getForId(fpr)]
  })).data
}

async function encrypt (message, fpr) {
  await load()
  return (await openpgp.encrypt({
    message: openpgp.message.fromText(message),
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
