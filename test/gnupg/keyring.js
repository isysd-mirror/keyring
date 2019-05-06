import assert from '../../../assert/assert.js'
import fs from '../../../fs/fs.js'
import { hostname, tmpdir, homedir } from '../../../os/os.js'
import { path } from '../../../path/path.js'
import { GnuPGKeyring } from '../../gnupg/keyring.js'
import { TRUST_LEVEL_ARRAY } from '../../keyring.js'
import { finishTest } from '../../../iso-test/index.js'
import { setup } from './setup.js'
import { cleanup } from './cleanup.js'
setup()
var keyring = new GnuPGKeyring()
var options = {}
var result = ''
var s
var keyid
var keyid2
var keyid3
var keyid4
var keyuid
var keyuid2
var keyuid3
var keyuid4
var gkeyid
var gkeyuid
var pubkeyex
var privkeyex
var sig
var sigi
var ciphertext
var cleartext
var cptext
var verified
const plaintext = 'hello world'
var fpr
var fpr2
var fpr3
var fpr4
const pubkey = fs.readFileSync('fixtures/pubkey.asc', 'ascii').trim()
const privkey = fs.readFileSync('fixtures/privkey.asc', 'ascii').trim()
const fpri = '230553D772BE56DD356248A0DE65B1508884AB5A'

try {
  keyring.keygenStream(options)
  options.stdin.on('data', data => {
    result = result + data
  })
  options.stdin.on('finish', e => {
    if (e) throw e
    assert(result.endsWith(`%commit
`))
    assert(result.indexOf(`Name-Real: ${process.env.USER}`) !== 1)
    assert(result.indexOf(`Name-Email: ${process.env.USER}@${hostname()}`) !== 1)
    assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
    assert(result.indexOf(`Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
`) !== 1)
    assert(result)
    finishTest('pass keyring.keygenStream default')
  })

  options = {
    'Key-Type': 'RSA'
  }
  result = ''
  keyring.keygenStream(options)
  options.stdin.on('data', data => {
    result = result + data
  })
  options.stdin.on('finish', e => {
    assert(result.endsWith(`%commit
`))
    assert(result.indexOf(`Name-Real: ${process.env.USER}`) !== 1)
    assert(result.indexOf(`Name-Email: ${process.env.USER}@${hostname()}`) !== 1)
    assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
    assert(result.indexOf(`Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
`) !== 1)
    assert(result)
    finishTest('pass keyring.keygenStream rsa')
  })

  options = {
    'Name-Real': 'user',
    'Name-Email': 'user@email',
    password: 'password'
  }
  result = ''
  keyring.keygenStream(options)
  options.stdin.on('data', data => {
    result = result + data
  })
  options.stdin.on('finish', e => {
    assert(result.endsWith(`%commit
`))
    assert(result.indexOf(`Passphrase: password`) !== 1)
    assert(result.indexOf(`Name-Real: user`) !== 1)
    assert(result.indexOf(`Name-Email: user@email`) !== 1)
    assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
    assert(result.indexOf(`Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
`) !== 1)
    assert(result)
    finishTest('pass keyring.keygenStream user pass')
  })

  options = {}
  result = ''
} catch (e) {
  cleanup()
  finishTest(e)
}

new Promise(async (resolve, reject) => {
  await keyring.init()
  finishTest('pass initialized keyring')

  keyid = await keyring.generate({
    'transient-key': true // Do not use this option outside of unit tests!
  })
  if (keyid) finishTest(`pass generate key ${keyid}`)
  else finishTest('fail generate key did not return keyid')
  keyuid = await keyring.list({ keys: keyid })
  assert(keyuid)
  finishTest(`pass list key ${JSON.stringify(keyuid, null, 2)}`)
  fpr = Object.keys(keyuid)[0]

  keyid2 = await keyring.generate({
    'transient-key': true, // Do not use this option outside of unit tests!
    'Name-Real': 'test2',
    'Name-Email': `test2@${hostname()}`
  })
  keyuid2 = await keyring.list({ keys: keyid2 })
  fpr2 = Object.keys(keyuid2)[0]
  options = { keys: fpr2 }
  keyring.stdinStream(options)
  options.stdin.end(`trust
3
y
quit
`)
  await keyring.editKey(options)
  options = { keys: fpr2 }
  await keyring.signKey(options)
  finishTest(`pass signKey ${fpr2} with ${fpr}`)

  keyid3 = await keyring.generate({
    'transient-key': true, // Do not use this option outside of unit tests!
    'Name-Real': 'test3',
    'Name-Email': `test3@${hostname()}`
  })
  keyuid3 = await keyring.list({ keys: keyid3 })
  fpr3 = Object.keys(keyuid3)[0]
  options = { keys: fpr3 }
  keyring.stdinStream(options)
  options.stdin.end(`trust
3
y
quit
`)
  await keyring.editKey(options)
  options = { keys: fpr3 }
  await keyring.signKey(options)

  keyid4 = await keyring.generate({
    'transient-key': true, // Do not use this option outside of unit tests!
    'Name-Real': 'test4',
    'Name-Email': `test4@${hostname()}`
  })
  keyuid4 = await keyring.list({ keys: keyid4 })
  fpr4 = Object.keys(keyuid4)[0]
  options = { keys: fpr4 }
  keyring.stdinStream(options)
  options.stdin.end(`trust
3
y
quit
`)
  await keyring.editKey(options)
  options = { keys: fpr4 }
  await keyring.signKey(options)

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

  sig = await keyring.sign({
    stdin: plaintext,
    keys: fpr,
    yes: true
  })
  assert(sig)
  finishTest(`pass signature stdin ${fpr} ${sig.slice(0, 20)}`)

  verified = await keyring.verify({
    stdin: sig
  })

  assert(verified)
  assert.equal(verified.length, 1)
  finishTest(`pass signature verify ${fpr} length`)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass signature verify ${fpr} trust`)
  assert.equal(verified[0].key, fpr)
  finishTest(`pass signature verify ${fpr} key`)
  assert.equal(verified[0].sigkey, fpr)
  finishTest(`pass signature verify ${fpr} sigkey`)
  assert(verified[0].time)
  finishTest(`pass signature verify ${fpr} time`)
  assert.equal(verified[0].uid, `${process.env.USER} <${process.env.USER}@${hostname()}>`)
  finishTest(`pass signature verified from ${fpr}`)

  sigi = await keyring.sign({
    stdin: plaintext,
    keys: fpri,
    yes: true
  })
  assert(sigi)
  finishTest(`pass signature stdin ${fpri} ${sigi.slice(0, 20)}`)

  options = { keys: fpri }
  keyring.stdinStream(options)
  options.stdin.end(`trust
1
y
quit
`)
  await keyring.editKey(options)
  options = { keys: fpri }

  verified = await keyring.verify({
    stdin: sigi
  })
  assert(verified)
  assert.equal(verified.length, 1)
  assert.equal(verified[0].trust, 1)
  assert.equal(verified[0].key, fpri)
  assert.equal(verified[0].sigkey, fpri)
  assert(verified[0].time)
  assert.equal(verified[0].uid, 'test <test@guld.io>')
  finishTest(`pass signature verify ${fpri} uid`)

  options = { keys: fpri }
  keyring.stdinStream(options)
  options.stdin.end(`trust
2
y
quit
`)
  await keyring.editKey(options)

  var verified = await keyring.verify({
    stdin: sigi
  })

  assert(verified)
  assert.equal(verified[0].trust, 1)
  finishTest(`pass signature verify ${fpri} trust never`)

  options = { keys: fpri }
  keyring.stdinStream(options)
  options.stdin.end(`trust
3
y
quit
`)
  await keyring.editKey(options)

  verified = await keyring.verify({
    stdin: sigi
  })
  assert(verified)
  assert.equal(verified[0].trust, 1)
  finishTest(`pass signature verify ${fpri} trust marginal`)

  await keyring.setConfig('default-key', [fpr2])
  options = { keys: fpri }
  await keyring.signKey(options)

  await keyring.setConfig('default-key', [fpr3])
  options = { keys: fpri }
  await keyring.signKey(options)

  await keyring.setConfig('default-key', [fpr4])
  options = { keys: fpri }
  await keyring.signKey(options)
  await keyring.setConfig('default-key', [fpr])

  verified = await keyring.verify({
    stdin: sigi
  })
  assert(verified)
  assert.equal(verified[0].trust, 4)
  finishTest(`pass signature verify ${fpri} trust 3 marginal signatures`)

  options = { keys: fpri }
  await keyring.signKey(options)

  verified = await keyring.verify({
    stdin: sigi
  })
  assert(verified)
  assert.equal(verified[0].trust, 4)
  finishTest(`pass signature verify ${fpri} trust marginal (signed)`)

  options = {
    'infile': path.join(process.env.GNUPGHOME, 'file.txt')
  }
  sig = await keyring.sign(options)
  assert(sig)
  finishTest(`pass sign infile ${sig.slice(0, 20)}`)

  verified = await keyring.verify({
    stdin: sig
  })

  assert(verified)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass sign infile verify ${sig.slice(0, 20)}`)

  options = {
    'infile': path.join(process.env.GNUPGHOME, 'file.txt'),
    'outfile': path.join(process.env.GNUPGHOME, 'file.txt.asc')
  }
  sig = await keyring.sign(options)
  assert.equal(sig, '')
  finishTest(`pass sign infile outfile ${sig}`)

  verified = await keyring.verify({
    infile: path.join(process.env.GNUPGHOME, 'file.txt.asc')
  })
  assert(verified)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass sign verify infile ${sig.slice(0, 20)}`)

  options = {
    'infile': path.join(process.env.GNUPGHOME, 'file.txt'),
    'armor': true,
    'detach': true
  }
  sig = await keyring.sign(options)
  assert(sig)
  finishTest(`pass detach-sign infile ${sig.slice(0, 20)}`)

  verified = await keyring.verify({
    infile2: path.join(process.env.GNUPGHOME, 'file.txt'),
    stdin: sig,
    detach: true
  })
  assert(verified)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass detach-sign verify infile2 stdin ${sig.slice(0, 20)}`)

  options = {
    'infile': path.join(process.env.GNUPGHOME, 'file.txt'),
    'outfile': path.join(process.env.GNUPGHOME, 'file.txt.asc'),
    'armor': true,
    'detach': true,
    yes: true
  }
  sig = await keyring.sign(options)
  assert.equal(sig, '')
  finishTest(`pass detach-sign infile outfile ${sig}`)

  verified = await keyring.verify({
    infile: path.join(process.env.GNUPGHOME, 'file.txt.asc'),
    infile2: path.join(process.env.GNUPGHOME, 'file.txt'),
    detach: true
  })
  assert(verified)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass detach-sign verify infile2 infile ${sig.slice(0, 20)}`)

  options = {
    'stdin': 'hello world',
    'armor': true,
    'detach': true,
    yes: true
  }
  sig = await keyring.sign(options)
  assert(sig)
  finishTest(`pass detach-sign stdin stdout ${sig.slice(0, 20)}`)
  var tmphome = path.join(tmpdir(), process.env.GNUPGHOME)

  await fs.promises.mkdirp(tmphome)
  await fs.promises.writeFile(path.join(tmphome, 'file.txt.asc'), sig)
  verified = await keyring.verify({
    infile: path.join(tmphome, 'file.txt.asc'),
    stdin: 'hello world',
    detach: true
  })
  assert(verified)
  assert.equal(verified[0].trust, 5)
  finishTest(`pass detach-sign verify tmp infile2 stdin ${sig.slice(0, 20)}`)

  ciphertext = await keyring.encrypt({
    stdin: plaintext,
    keys: fpri
  })

  cptext = await keyring.decrypt({
    stdin: ciphertext
  })

  assert(cptext === plaintext)
  finishTest(`pass decrypt stdin ${cptext}`)

  await keyring.delete({
    'keys': fpri,
    secret: true
  })

  keyuid = await keyring.list({ keys: fpri }).catch(e => undefined)
  assert(keyuid === undefined)
  finishTest(`pass delete key ${JSON.stringify(fpri, null, 2)}`)

  resolve()
}).then(() => {
  new Promise(async (resolve, reject) => {
    s = keyring.generateStream({
      'transient-key': true // Do not use this option outside of unit tests!
    })
    s.setEncoding('utf-8')
    s.on('data', d => {
      gkeyid = d
    })
    s.on('error', finishTest)
    s.on('finish', (e) => {
      if (e) finishTest(e)
      if (gkeyid) finishTest(`pass generateStream key ${gkeyid}`)
      else finishTest(`fail generateStream key did not return keyid, out: ${gkeyid}`)
      s = keyring.listStream({ keys: gkeyid })
      s.setEncoding('utf-8')
      s.on('data', d => {
        gkeyuid = d
      })
      s.on('error', finishTest)
      s.on('finish', (e) => {
        if (e) finishTest(e)
        var fpr = gkeyuid.split('::')[0]
        assert(fpr.endsWith(gkeyid.slice(2)))
        finishTest(`pass listStream key ${gkeyuid}`)
        s = keyring.deleteStream({ keys: fpr, secret: true })
        s.setEncoding('utf-8')
        s.on('data', process.stdout.write)
        s.on('error', process.stderr.write)
        s.on('close', (e) => {
          if (e) finishTest(e)
          gkeyuid = undefined
          s = keyring.listStream({ keys: gkeyid })
          s.setEncoding('utf-8')
          s.on('data', d => {
            gkeyuid = d
          })
          s.on('error', finishTest)
          s.on('finish', (e) => {
            if (e) finishTest(e)
            if (gkeyuid === undefined) finishTest(`pass deleteStream key ${gkeyid}`)
            else finishTest(`fail deleteStream key did not delete keyid, out: ${gkeyid}`)
            //cleanup()
            finishTest('kill')
            resolve()
          })
        })
      })
    })
  }).catch(e => {
    console.error(e)
    cleanup()
    finishTest(e)
  })
}).catch(e => {
  console.error(e)
  cleanup()
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
