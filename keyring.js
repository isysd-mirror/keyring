const spawn = require('child_process').spawn
const pify = require('pify')
const rimraf = pify(require('rimraf'))
const fs = pify(require('fs'))
const fpre = /[A-Z0-9]{40}/gm
const { homedir, tmpdir } = require('os')
const path = require('path')
// set GNUPGHOME to default if it isn't already
if (!process.env.hasOwnProperty('GNUPGHOME')) process.env.GNUPGHOME = path.join(homedir(), '.gnupg')

function getGpgAgentRe (grip) {
  return new RegExp(`^S KEYINFO ${grip} [DP1 -]{0,20}\nOK\n*$`)
}

async function scall (command, stdin, args = [], redirectErr = false) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args)
    const buffers = []
    let buffersLength = 0
    let stderr = ''
    proc.stdout.on('data', function (buf) {
      buffers.push(buf)
      buffersLength += buf.length
    })
    proc.stderr.on('data', function (buf) {
      if (!redirectErr) {
        stderr += buf.toString('utf8')
      } else {
        buffers.push(buf)
        buffersLength += buf.length
      }
    })
    proc.on('close', function (code) {
      var stdout = Buffer.concat(buffers, buffersLength)
      if (code !== 0 && stderr !== '') reject(new Error(stderr))
      stdout = stdout.toString('utf-8')
      resolve(stdout)
    })
    proc.stdin.end(stdin)
  })
}

async function generate (options) {
  options.numBits = options.numBits || 4096
  var opstr = `
Key-Type: RSA
Key-Length: ${options.numBits}
Subkey-Type: RSA
Subkey-Length: ${options.numBits}
Name-Real: ${options.userIds[0].name}
Name-Email: ${options.userIds[0].email}
Expire-Date: 0
`
  if (options.passphrase) {
    opstr = `${opstr}Passphrase: ${options.passphrase}\n`
  }
  opstr = `${opstr}%commit\n`
  var resp = await scall('gpg2', opstr, ['--batch', '--generate-key'], true)
  var r = resp.match(/key [A-Z0-9]{16} marked as ultimately trusted/)
  if (r === null) throw new Error(`Unable to generate key, output ${resp}`)
  r = r[0].match(/[A-Z0-9]{16}/)
  var keys = await listKeys(r[0])
  return keys[Object.keys(keys)[0]]
}

async function clear () {
  await rimraf(`${process.env.GNUPGHOME}.bak`).catch()
  try {
    await fs.rename(process.env.GNUPGHOME, `${process.env.GNUPGHOME}.bak`)
    await store().catch()
  } catch (e) {
    await store().catch()
  }
}

async function store () {
  await scall(`gpg2`, '', ['--list-public-keys'], true)
  await fs.mkdir(path.join(process.env.GNUPGHOME, 'private-keys-v1.d'), 0o700)
}

async function getKeygrips (fpr) {
  var data = await scall('gpg2', '', ['--fingerprint', '--with-keygrip', fpr])
  return data.toString('utf-8').match(fpre)
}

async function listKeys (fpr) {
  var keys = {}
  var args = ['--list-keys', '--with-colons']
  if (fpr) args.push(fpr)
  var data = await scall('gpg2', '', args)
  var da = data.toString('utf-8')
  da = da.match(/fpr.*[\n]+.*uid.*::::::::::/g)
  if (da) {
    for (var l in da) {
      var fpr2 = da[l].match(/[A-Z0-9]{40}/g)[0]
      var uid = da[l].match(/[A-Z0-9]{40}::[^:]+/)[0].split(':')
      if (uid) keys[fpr2] = uid.slice(-1)[0]
      else keys[fpr2] = keys[fpr2]
    }
  }
  return keys
}

async function listSecretKeys (term) {
  var keys = {}
  var args = ['--list-secret-keys', '--with-colons']
  if (term) args.push(term)
  var data = await scall('gpg2', '', args)
  var da = data.toString('utf-8')
  da = da.match(/sec.*[\n]+.*[A-Z0-9]{40}.*[\n]*.*[\n]*.*uid.*::::::::::/g)
  if (da) {
    for (var l in da) {
      var fpr = da[l].match(/[A-Z0-9]{40}/g)[0]
      var uid = da[l].match(/[A-Z0-9]{40}::[^:]+/)[0].split(':')
      if (uid) keys[fpr] = uid.slice(-1)[0]
      else keys[fpr] = keys[fpr]
    }
  }
  return keys
}

async function importPublicKey (key) {
  await scall('gpg2', key, ['--batch', '--import'], true)
}

async function importSecretKey (key, pass) {
  var args = ['--import', '--allow-secret-key-import']
  if (pass) {
    args.unshift(pass)
    args.unshift('--passphrase')
    args.unshift('--batch')
  }
  var resp = await scall('gpg2', key, args, true)
  var r = resp.match(/key [A-Z0-9]{16}: secret key imported/)
  if (r === null) throw new Error(`Unable to import key, output ${resp}`)
  r = r[0].match(/[A-Z0-9]{16}/)
  var keys = await listKeys(r[0])
  var fpr = keys[Object.keys(keys)[0]]
  await scall('gpg2', 'trust\n5\ny\nsave\n', ['--command-fd=0', '--edit-key', fpr], true)
  return fpr
}

async function getPublicKey (fpr) {
  return scall('gpg2', '', ['-a', '--export', fpr])
}

async function getSecretKey (fpr, pass) {
  var args = ['-a', '--export-secret-keys', fpr]
  if (pass) {
    args.unshift(pass)
    args.unshift('--passphrase')
    args.unshift('--batch')
  }
  return scall('gpg2', '', args)
}

async function isLocked (fpr) {
  const keygrips = await getKeygrips(fpr)
  const stdout = await scall('gpg-connect-agent', `KEYINFO --no-ask ${keygrips[0]} Err Pmt Des`)
  return !getGpgAgentRe(keygrips[0]).test(stdout)
}

async function unlockKey (fpr, pass) {
  var args = ['--detach-sign', '-a', '-u', fpr]
  if (pass) {
    args.unshift(pass)
    args.unshift('--passphrase')
    args.unshift('--batch')
  }
  if (await this.isLocked(fpr)) await scall('gpg2', 'hello', args)
}

async function lockKey (fpr, pass) {
  await scall('gpg-connect-agent', '', ['reloadagent', '/bye'])
}

async function sign (message, fpr) {
  return scall('gpg2', message, ['--detach-sign', '-a', '-u', fpr])
}

async function verify (message, signature, signers) {
  if (!Array.isArray(signers)) signers = [signers]
  var tmpfile = path.join(tmpdir(), `${Date.now()}.sig`)
  await fs.writeFile(tmpfile, signature)
  var res = await scall('gpg2', message, ['--status-fd=1', '--verify', tmpfile, '-'], true)
  await fs.unlink(tmpfile)
  // TODO check response against signers
  var active
  var sigqual
  var validsig
  res = res.split('\n')
  for (var line in res) {
    if (res[line].startsWith('[GNUPG:] NEWSIG')) {
      active = undefined
      sigqual = undefined
      validsig = undefined
    } else if (res[line].startsWith('[GNUPG:] KEY_CONSIDERED')) {
      active = res[line].match(fpre)[0]
    } else if (res[line].startsWith('[GNUPG:] GOODSIG')) {
      sigqual = 'good'
    } else if (res[line].startsWith('[GNUPG:] VALIDSIG')) {
      validsig = true
    }
    // TODO other sig qualities to allow? configurable?
    if (active && validsig && sigqual && sigqual === 'good') {
      var si = signers.indexOf(active)
      if (si !== -1) signers.splice(si, 1)
    }
  }
  return signers.length === 0
}

async function decrypt (message) {
  return scall('gpg2', message, ['-d'])
}

async function encrypt (message, fpr) {
  return scall('gpg2', message, ['-a', '-e', '-r', fpr])
}

async function decryptFile (i) {
  return scall('gpg2', '', ['-d', i])
}

async function encryptFile (i, fpr) {
  return scall('gpg2', '', ['-a', '-e', '-r', fpr, i])
}

async function decryptToFile (message, i) {
  return scall('gpg2', message, ['-o', i, '-d'])
}

async function encryptToFile (message, i, fpr) {
  return scall('gpg2', message, ['-o', i, '-a', '-e', '-r', fpr])
}

async function decryptFileToFile (i, o) {
  return scall('gpg2', '', ['-o', o, '-d', i])
}

async function encryptFileToFile (i, o, fpr) {
  return scall('gpg2', '', ['-o', o, '-a', '-e', '-r', fpr, i])
}

module.exports = {
  generate: generate,
  clear: clear,
  store: store,
  listKeys: listKeys,
  listSecretKeys: listSecretKeys,
  importPublicKey: importPublicKey,
  importSecretKey: importSecretKey,
  getPublicKey: getPublicKey,
  getSecretKey: getSecretKey,
  isLocked: isLocked,
  unlockKey: unlockKey,
  lockKey: lockKey,
  sign: sign,
  verify: verify,
  decrypt: decrypt,
  encrypt: encrypt,
  decryptFile: decryptFile,
  encryptFile: encryptFile,
  decryptToFile: decryptToFile,
  encryptToFile: encryptToFile,
  decryptFileToFile: decryptFileToFile,
  encryptFileToFile: encryptFileToFile,
  fpre: fpre
}
