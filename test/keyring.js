import assert from '../../assert/assert.js'
import fs from '../../fs/fs.js'
import { GnuPGKeyring } from '../gnupg/keyring.js'
import { gpgKeygenStream } from '../gnupg/commands.js'
import { finishTest } from '../../iso-test/index.js'
var keyring = new GnuPGKeyring()
var options = {}
var s
var keyid
var keyuid
var gkeyid
var gkeyuid
var pubkeyex
var privkeyex
var sig
var ciphertext
var cleartext
var cptext
const plaintext = 'hello world'
var fpr
const pubkey = fs.readFileSync('fixtures/pubkey.asc', 'ascii').trim()
const privkey = fs.readFileSync('fixtures/privkey.asc', 'ascii').trim()
const fpri = '230553D772BE56DD356248A0DE65B1508884AB5A'
// process.env.GNUPGHOME = path.resolve('fixtures')

new Promise(async (resolve, reject) => {
  await keyring.init()
  finishTest('pass initialized keyring')

  keyid = await keyring.generate({
    'transientKey': true // Do not use this option outside of unit tests!
  })
  if (keyid) finishTest(`pass generate key ${keyid}`)
  else finishTest('fail generate key did not return keyid')
  keyuid = await keyring.list({ keys: keyid })
  assert(keyuid)
  finishTest(`pass list key ${JSON.stringify(keyuid, null, 2)}`)
  fpr = Object.keys(keyuid)[0]

  await keyring.import({
    stdin: pubkey
  })

  keyuid = await keyring.list({ keys: fpri })
  assert(keyuid)
  finishTest(`pass import key ${fpri}`)

  pubkeyex = await keyring.export({
    keys: fpri,
    armor: true
  })
  assert(pubkeyex.trim('\n') === pubkey.trim('\n'))
  finishTest(`pass export key ${fpri}`)

  keyuid = await keyring.list({ keys: fpri, secret: true }).catch(e => undefined)
  assert(keyuid === undefined)
  finishTest(`pass import key no secret ${fpri}`)

  await keyring.import({
    stdin: privkey,
    secret: true
  })

  keyuid = await keyring.list({ keys: fpri, secret: true })
  assert(keyuid)
  finishTest(`pass import secret key ${fpri}`)

  privkeyex = await keyring.export({
    keys: fpri,
    secret: true,
    armor: true
  })
  assert(privkeyex.trim('\n') === privkey.trim('\n'))
  finishTest(`pass export secret key ${fpri}`)

  await keyring.delete({
    'keys': fpr,
    secret: true
  })

  keyuid = await keyring.list({ keys: fpr }).catch(e => undefined)
  assert(keyuid === undefined)
  finishTest(`pass delete key ${JSON.stringify(fpr, null, 2)}`)

  sig = await keyring.sign({
    stdin: plaintext,
    keys: fpri
  })

  assert(sig)
  finishTest(`pass signature stdin ${sig.slice(0, 20)}`)  

  ciphertext = await keyring.encrypt({
    stdin: plaintext,
    keys: fpri
  })

  assert(ciphertext)
  finishTest(`pass encrypt stdin ${ciphertext.slice(0, 20)}`)  

  cptext = await keyring.decrypt({
    stdin: ciphertext
  })

  assert(cptext === plaintext)
  finishTest(`pass decrypt stdin ${cptext}`)  

  await keyring.delete({
    'keys': fpr,
    secret: true
  })

  resolve()
}).then(() => {
  new Promise(async (resolve, reject) => {
    s = keyring._generate({
      'password': 'password'
    })
    s.setEncoding('utf-8')
    s.on('data', d => {
      gkeyid = d
    })
    s.on('error', finishTest)
    s.on('finish', (e) => {
      if (e) finishTest(e)
      if (gkeyid) finishTest(`pass _generate key ${gkeyid}`)
      else finishTest(`fail _generate key did not return keyid, out: ${gkeyid}`)
      s = keyring._list({keys: gkeyid})
      s.setEncoding('utf-8')
      s.on('data', d => {
        gkeyuid = d
      })
      s.on('error', finishTest)
      s.on('finish', (e) => {
        if (e) finishTest(e)
        var fpr = gkeyuid.split('::')[0]
        assert(fpr.endsWith(gkeyid.slice(2)))
        finishTest(`pass _list key ${gkeyuid}`)
        s = keyring._delete({keys: fpr, secret: true})
        s.setEncoding('utf-8')
        s.on('data', process.stdout.write)
        s.on('error', process.stderr.write)
        s.on('close', (e) => {
          if (e) finishTest(e)
          gkeyuid = undefined
          s = keyring._list({keys: gkeyid})
          s.setEncoding('utf-8')
          s.on('data', d => {
            gkeyuid = d
          })
          s.on('error', finishTest)
          s.on('finish', (e) => {
            if (e) finishTest(e)
            if (gkeyuid === undefined) finishTest(`pass _delete key ${gkeyid}`)
            else finishTest(`fail _delete key did not delete keyid, out: ${gkeyid}`)
            resolve()
          })
        })
      })
    })
  }).catch(e => {
    console.error(e)
    finishTest(e)
  })
}).catch(e => {
  console.error(e)
  finishTest(e)
})



/*

this.fpr = await gpg.generate({
  passphrase: 'password',
  numBits: 1024,
  userIds: [{
    name: 'testu',
    email: 'testu@guld.io'
  }]
})
assert.exists(this.fpr)

pubkey = (await gpg.getPublicKey(this.fpr)).trim()
await fs.writeFile('fixtures/pubkey.asc')
privkey = (await gpg.getSecretKey(this.fpr)).trim()
await fs.writeFile('fixtures/privkey.asc')

await gpg.importPublicKey(pubkey)
  assert.isTrue(true)
})

this.pubkey = await gpg.getPublicKey(fpr)
assert.equal(this.pubkey.trim(), pubkey)

assert(Object.keys(await gpg.listKeys()).length === 2)

assert(Object.keys(await gpg.listSecretKeys()).length === 1)

await gpg.importSecretKey(privkey, 'password')
this.privkey = await gpg.getSecretKey(fpr, 'password')
assert.exists(this.privkey.match('-----BEGIN PGP PRIVATE KEY BLOCK-----'))

var islocked = await gpg.isLocked(fpr)
assert.isNotTrue(islocked)
//  await gpg.lockKey(fpr, 'password')
//  var islocked = await gpg.isLocked(fpr)
//  assert.isTrue(islocked)

await gpg.unlockKey(fpr, 'password')
var islocked = await gpg.isLocked(fpr)
assert.exists(islocked)
assert.isNotTrue(islocked)

this.sig = await gpg.sign('hello', fpr)
assert.exists(this.sig)
assert.equal(typeof this.sig, 'string')

var verified = await gpg.verify('hell', this.sig, fpr)
assert.exists(verified)
assert.isFalse(verified)

var verified = await gpg.verify('hello', this.sig, fpr)
assert.exists(verified)
assert.isTrue(verified)

this.ciphertext = await gpg.encrypt('hello', fpr)
assert.exists(this.ciphertext)
assert.equal(typeof this.ciphertext, 'string')

var message = await gpg.decrypt(this.ciphertext, fpr)
assert.exists(message)
assert.equal(message, 'hello')
*/
