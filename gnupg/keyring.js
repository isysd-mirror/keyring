import assert from '../../assert/assert.js'
import path from '../../path/path.js'
// import util from '../util/util.js'
import fs from '../../fs/fs.js'
import { tmpdir, hostname } from '../../os/os.js'
import global from '../../global/global.js'
import { Process } from '../../process/process.js'
import { Transform, Readable } from '../../stream/stream.js'
import child_process from '../../child_process/child_process.js'
import { randStr, randTimestamp } from '../../random/random.js'
import { Keyring, keyIdRe } from '../keyring.js'
import { secretKeyImportReducer, fprUidReducer, colonListReducer, keyTrustedReducer, verifySigReducer } from './reducers.js'
import { senseGpgExec } from './executables.js'
// import { createGnuPG } from './gnupg.js'
import config from './config.js'
global.process = Process.getProcess()

/*
 * Command argument generators
 */
const COMMAND_ARGS = {
  'encrypt': ['-e'],
  'decrypt': ['-d'],
  'verify': ['--verify'],
  'sign': ['--clear-sign'],
  'detach-sign': ['--detach-sign'],
  'list': ['--list-keys', '--with-colons'],
  'list-secret': ['--list-secret-keys', '--with-colons'],
  'import': ['--import'],
  'import-secret': ['--import', '--allow-secret-key-import'],
  'export': ['--export'],
  'export-secret': ['--export-secret-keys'],
  'delete': ['--delete-keys'],
  'delete-secret': ['--delete-secret-and-public-key'],
  'generate': ['--generate-key'],
  'edit-key': ['--command-fd=0', '--no-tty', '--edit-key'],
  'sign-key': ['--sign-key']
}

const OUT_FILE_COMMANDS = [
  'encrypt',
  'decrypt',
  'sign',
  'detach-sign',
  'export',
  'export-secret'
]

const IN_FILE_COMMANDS = [
  'decrypt',
  'import',
  'import-secret'
]


export function setCommandArgs (options, args) {
  if (options.command) {
    COMMAND_ARGS[options.command].forEach(c => c && c.length ? args.push(c) : null)
    switch (options.command) {
      case 'list':
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'list-secret':
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'import':
        setBatchArgs(options, args)
        setFileArgs(options, args)
        break
      case 'import-secret':
        setArmorArgs(options, args)
        setBatchArgs(options, args)
        setPassArgs(options, args)
        setFileArgs(options, args)
        break
      case 'export':
        setArmorArgs(options, args)
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'export-secret':
        setArmorArgs(options, args)
        setBatchArgs(options, args)
        setPassArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'encrypt':
        setArmorArgs(options, args)
        setBatchArgs(options, args)
        setFileArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'decrypt':
        setBatchArgs(options, args)
        setFileArgs(options, args)
        break
      case 'delete':
      case 'delete-secret':
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'verify':
        setBatchArgs(options, args)
        setFileArgs(options, args)
        break
      case 'generate':
        setBatchArgs(options, args)
        setPassArgs(options, args)
        break
      case 'edit-key':
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'sign-key':
        setBatchArgs(options, args)
        setKeyArgs(options, args)
        break
      case 'sign':
      default:
        setArmorArgs(options, args)
        setBatchArgs(options, args)
        setPassArgs(options, args)
        setFileArgs(options, args)
        setKeyArgs(options, args)
        if (options.clear === false || options.detach) {
          if (args.indexOf('--detach-sign') === -1) args[args.indexOf('--clear-sign')] = '--detach-sign'
        }
        break
    }
  }
}

function setFileArgs (options, args) {
  if (options.outfile) {
    args.unshift(options.outfile)
  } else if (options.command === 'verify') {
    args.unshift('--status-fd=1')
  }
  if (OUT_FILE_COMMANDS.indexOf(options.command) !== -1 && args.indexOf('-o') === -1) {
    if (typeof(options.outfile) === 'undefined') args.unshift('-')
    args.unshift('-o')
  }
  if (options.infile && IN_FILE_COMMANDS.indexOf(options.command) !== -1 && args.indexOf('-i') === -1) {
    args.unshift(options.infile)
    args.unshift('-i')
  } else if (options.infile && args.indexOf(options.infile) === -1) {
    args.push(options.infile)
  } else if (options.command === 'verify' && options.detach) {
    args.push('-')
  }
  if (options.infile2) {
    args.push(options.infile2)
  } else if (options.command === 'verify' && options.detach) {
    args.push('-')
  }

}

function setKeyArgs (options, args) {
  if (typeof options.keys === 'string') options.keys = [options.keys]
  if (options.keys) {
    if (options.command && options.command === 'encrypt') {
      if (args.indexOf('-r') > -1) return // already set, don't append
      args.push('-r')
    } else if (options.command && options.command === 'sign') {
      if (args.indexOf('-u') > -1) return // already set, don't append
      args.push('-u')
    }
    options.keys.forEach(k => {
      if (args.indexOf(k) === -1) args.push(k)
    })
  }
}

function setArmorArgs (options, args) {
  if (options.armor) {
    if (args.indexOf('-a') === -1) args.unshift('-a')
  }
}

function setBatchArgs (options, args) {
  if (options.yes || options.command === 'generate'  || options.command === 'sign-key' || options.command.startsWith('delete') || options.password || options.batch) {
    if (args.indexOf('--batch') === -1) args.unshift('--batch')
    if (args.indexOf('--yes') === -1) args.unshift('--yes')
  }
}

function setPassArgs (options, args) {
  options.password = options.password || options['Passphrase']
  if (options.password) {
    setBatchArgs(options, args)
    if (args.indexOf('--passphrase') === -1) args.push('--passphrase')
    if (args.indexOf(options.password) === -1) args.push(options.password)
  }
}

/*
 * Main Keyring class extends GnuPG, GnuPGConfig, Keyring
 */

export class GnuPGKeyring extends config.createGnuPGConfig(Keyring) {
  constructor (options) {
    options = options || {}
    super(options)
  }

  static setCommandArgs (options, args) {
    return setCommandArgs(options, args)
  }

  /*
   * Configuration helpers
   */

  get config () {
    // the cached config object
    return this._config
  }

  get __gpg () {
    // the cached path to GnuPG executable or default gpg2
    return process.env.GNUPG_EXEC || 'gpg2'
  }

  async init () {
    process.env.GNUPG_EXEC = await senseGpgExec()
    await this.initConfig()
    await this.list({ keys: process.env.USER }).catch(e => undefined)
    await fs.promises.mkdir(path.join(this.home, 'private-keys-v1.d'), {
      recursive: true,
      mode: 0o700
    }).catch(e => {
      if (e.toString().indexOf('EEXIST') === -1) throw e
    })
  }

  stdinStream (options) {
    options = options || {}
    options.stdin = new Transform({ transform: function (chunk, enc, cb) {
      this.push(chunk)
      cb()
    } })
    options.stdin.setEncoding('utf-8')
  }

  // editKeyStream () {}

  keygenStream (options) {
    this.stdinStream(options)
    // initialize async environment to push to options.stdin
    new Promise(async (resolve, reject) => {
      var keygen = await this.getConfig('keygen.conf').catch(e => config.DEFAULTS['keygen.conf'])
      options['Key-Type'] = options['Key-Type'] || keygen['Key-Type'].args[keygen['Key-Type'].args.length - 1]

      // default creation time is random time in last ~1 day
      options['Creation-Date'] = options['Creation-Date'] || 'seconds=' + (await randTimestamp()).toString()
      // default expiration 10 years in the future
      options['Expire-Date'] = options['Expire-Date'] || parseInt(options['Creation-Date'].slice(7)) + 315360000
      if (keygen && keygen['Key-Type']) assert(keygen['Key-Type'].args.indexOf(options['Key-Type']) !== -1)

      switch (options['Key-Type'].toLowerCase()) {
        case 'rsa':
          options['Key-Length'] = options['Key-Length'] || keygen['Key-Length'].args[keygen['Key-Length'].args.length - 1]
          options.stdin.write(`Key-Type: RSA
Key-Length: ${options['Key-Length']}
Subkey-Type: RSA
Subkey-Length: ${options['Key-Length']}
`)
        case 'ecc':
        case 'eddsa':
        case 'ecdh':
        default:
          options['Key-Curve'] = options['Key-Curve'] || keygen['Key-Curve'].args[keygen['Key-Curve'].args.length - 1]
          options['Subkey-Curve'] = options['Key-Curve'] === 'Ed25519' ? 'Curve25519' : options['Key-Curve']
          options.stdin.write(`Key-Type: eddsa
Key-Curve: ${options['Key-Curve']}
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: ${options['Subkey-Curve']}
Subkey-Usage: encrypt
`)
          break
      }
      if (options['Expire-Date']) {
        options.stdin.write(`Expire-Date: ${options['Expire-Date']}
`)
      }
      if (options['Creation-Date']) {
        options.stdin.write(`Creation-Date: ${options['Creation-Date']}
`)
      }
      options['Name-Real'] = options['Name-Real'] || process.env.USER
      options['Name-Email'] = options['Name-Email'] || `${process.env.USER}@${hostname()}`
      if (options['Name-Real']) {
        options.stdin.write(`Name-Real: ${options['Name-Real']}
`)
      }
      if (options['Name-Email']) {
        options.stdin.write(`Name-Email: ${options['Name-Email']}
`)
      }
      options.password = options.password || options['Passphrase']
      if (options.password) {
        options.stdin.write(`Passphrase: ${options.password}
`)
      } else if (options['transient-key']) {
        options.stdin.write(`%no-protection
%transient-key
`)
      }
      options.stdin.write(`%commit
`)
      options.stdin.end()
    })
    return options.stdin
  }

  /*
   * Raw process API
   */
  _gpg (args, options) {
    options = options || {}
    options.windowsHide = true
    options.env = process.env
    if (process.env.DEBUG) {
      process.stdout.write(`${this.__gpg} ${args.join(' ')}
`)
    }
    return child_process.spawn(this.__gpg, args, options)
  }

  /*
   * Stream API
   */
  generateStream (options) {
    var args = []
    options = options || {}
    options.command = 'generate'
    options.stdin = options.stdin || this.keygenStream(options)
    setCommandArgs(options, args)
    var p = this._gpg(args)
    options.stdin.pipe(p.stdin)
    p.stdout.setEncoding('utf-8')
    p.stderr.setEncoding('utf-8')
    p.stdout.on('close', () => {
      p.stderr.destroy()
    })
    return p.stderr
      .pipe(new Transform({
        transform: keyTrustedReducer
      }))
  }

  importStream (options) {
    assert(options.stdin.length >= 40 || options.filein.length >= 40)
    var args = []
    options.command = 'import'
    if (options.secret) options.command = 'import-secret'
    var s = this._gpg(args)
      .streamify(options.stdin)
    if (options.secret) {
      s.pipe(new Transform({
        transform: secretKeyImportReducer,
        encoding: 'utf-8'
      }))
        .pipe(new Transform({
          transform: fprUidReducer,
          encoding: 'utf-8'
        }))
    }
  }

  deleteStream (options) {
    var args = []
    options = options || {}
    options.command = 'delete'
    if (options.secret) options.command = 'delete-secret'
    setCommandArgs(options, args)
    var p = this._gpg(args)
    return p.stdout
  }

  listStream (options) {
    var args = []
    options.command = 'list'
    if (options.secret) options.command = 'list-secret'
    setCommandArgs(options, args)
    return this._gpg(args).streamify(options.stdin)
      .pipe(new Transform({
        transform: colonListReducer,
        encoding: 'utf-8'
      })).pipe(new Transform({
        transform: fprUidReducer,
        encoding: 'utf-8'
      }))
  }

  signStream (options) {
    var args = []
    options.command = 'sign'
    setCommandArgs(options, args)
    return this._gpg(args)
      .streamify(options.stdin)
  }

  verifyStream (options) {
    var args = []
    options.command = 'verify'
    setCommandArgs(options, args)
    var p = this._gpg(args)
    if (options.stdin) {
      try {
        options.stdin.pipe(p.stdin)
      } catch (e) {
        if (e instanceof TypeError) p.stdin.end(options.stdin)
      }
    }
    p.stdout.setEncoding('utf-8')
    p.stderr.setEncoding('utf-8')
    if (process.env.DEBUG && process.stderr) p.stderr.pipe(process.stderr)
    return p.stdout.pipe(new Transform({
      transform: verifySigReducer,
      encoding: 'utf-8'
    }))
  }

  encryptStream (options) {
    var args = []
    options.command = 'encrypt'
    setCommandArgs(options, args)
    return this._gpg(args).streamify(options.stdin)
  }

  decryptStream (options) {
    var args = []
    options.command = 'decrypt'
    setCommandArgs(options, args)
    return this._gpg(args).streamify(options.stdin)
  }

  editKeyStream (options) {
    var args = []
    options.command = 'edit-key'
    setCommandArgs(options, args)
    return this._gpg(args).streamify(options.stdin)
  }

  /*
   * Promise API methods
   */
  async generate (options) {
    return new Promise(async (resolve, reject) => {
      var keyid
      var s = this.generateStream(options)
      s.setEncoding('utf-8')
      s.on('data', d => {
        keyid = d
      })
      s.on('error', e => {
        reject(e)
      })
      s.on('finish', (e) => {
        if (e) reject(e)
        else if (keyid) resolve(keyid)
        else reject(new Error('no key id for supposedly generated key'))
      })
    })
  }

  async delete (options) {
    return new Promise(async (resolve, reject) => {
      var s = this.deleteStream(options)
      s.setEncoding('utf-8')
      s.on('data', d => {
        // DEBUG
        process.stdout.write(d)
      })
      s.on('error', e => {
        reject(e)
      })
      s.on('close', e => {
        if (e) reject(e)
        else resolve()
      })
    })
  }

  async getKeygrips (fpr) {
    var data = await this._gpg(['--fingerprint', '--with-keygrip', fpr])
    return data.toString('utf-8').match(fpre)
  }

  async list (options) {
    var keys = {}
    var found = false
    return new Promise(async (resolve, reject) => {
      var s = this.listStream(options)
      s.setEncoding('utf-8')
      s.on('data', d => {
        if (d && d.split) {
          var k = d.split('::')
          keys[k[0]] = k[1]
          found = true
        }
      })
      s.on('error', e => {
        reject(e)
      })
      s.on('finish', () => {
        if (found) resolve(keys)
        else reject(new Error(`no keys found for search ${options.keys}`))
      })
    })
  }

  async import (options) {
    var args = []
    options = options || {}
    options.command = 'import'
    if (options.secret) options.command = 'import-secret'
    setCommandArgs(options, args)
    return new Promise(async (resolve, reject) => {
      var s = this._gpg(args)
      s.stdin.end(options.stdin)
      s.stdout.setEncoding('utf-8')
      s.stderr.setEncoding('utf-8')
      s.stdout.on('data', d => {
        if (process.env.DEBUG) process.stderr.write(`${d.trim('\n')}\n`)
      })
      s.stdout.on('error', e => {
        reject(e)
      })
      s.stderr.on('data', d => {
        if (process.env.DEBUG) process.stderr.write(`${d.trim('\n')}\n`)
      })
      s.stderr.on('error', e => {
        reject(e)
      })
      s.stdout.on('close', (e) => {
        if (e) reject(e)
        else resolve()
      })
      s.stderr.on('close', (e) => {
        if (e) reject(e)
        else resolve()
      })
    })
  }

  async export (options) {
    var args = []
    options = options || {}
    options.command = 'export'
    if (options.secret) options.command = 'export-secret'
    setCommandArgs(options, args)
    return new Promise(async (resolve, reject) => {
      var s = this._gpg(args)
      var key = Buffer.from('')
      s.stdin.end(options.stdin)
      s.stdout.on('data', d => {
        key = Buffer.concat([key, d])
      })
      s.stdout.on('error', e => {
        reject(e)
      })
      s.stderr.on('data', d => {
        if (process.env.DEBUG) process.stderr.write(`stderr data ${d}`)
      })
      s.stderr.on('error', e => {
        reject(e)
      })
      s.stdout.on('close', (e) => {
        if (e) reject(e)
        else if (key.length === 0) reject('Unable to export key')
        else {
          if (options.armor) resolve(key.toString('utf-8'))
          else resolve(key)
        }
      })
      s.stderr.on('close', (e) => {
        if (e) reject(e)
        else if (key.length === 0) reject('Unable to export key')
        else {
          if (options.armor) resolve(key.toString('utf-8'))
          else resolve(key)
        }
      })
    })
  }

  /*
    if (typeof signers === 'string') signers = [signers]
    if (!weights || weights.length === 0) {
      weights = []
      signers.forEach(s => {
        weights.push(1)
      })
    }
    if (typeof signature === 'undefined' || typeof message === 'undefined') throw new Error(`message and/or signature are blank`)
    var rnd = await randStr(8)
    var tmpfile = path.join(tmpdir(), `${Date.now()}${rnd}.sig`)
    await fs.writeFile(tmpfile, signature)
    var res = await spawn('gpg2', message, ['--status-fd=1', '--verify', tmpfile, '-'], true)
    var active
    var sigqual
    var validsig
    var votes = 0
    res = res.replace(/\n$/, '')
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
        if (si !== -1) {
          signers.splice(si, 1)
          if (weights && weights.length >= si - 1) {
            votes = votes + weights[si]
            weights.splice(si, 1)
          }
        }
      }
    }
    await fs.unlink(tmpfile).catch(e => {})
    return votes
  */

  async verify (options) {
    var sigs = []
    var s = this.verifyStream(options)
    return new Promise((resolve, reject) => {
      s.setEncoding('utf-8')
      s.on('data', d => {
        var da = d.split(' ')
        sigs.push({
          'sigkey': da[0],
          'key': da[1],
          'time': parseInt(da[2]),
          'trust': parseInt(da[3]),
          'uid': da.slice(4).join(' ')
        })
      })
      s.on('error', e => {
        reject(e)
      })
      s.on('end', e => {
        if (e) reject(e)
        resolve(sigs)
      })
    })
  }

  async sign (options) {
    var args = []
    options.command = 'sign'
    options.armor = options.armor || true
    setCommandArgs(options, args)
    return this._gpg(args).promisify(options.stdin)
  }

  async encrypt (options) {
    var args = []
    options.command = 'encrypt'
    options.armor = options.armor || true
    setCommandArgs(options, args)
    return this._gpg(args).promisify(options.stdin)
  }

  async decrypt (options) {
    var args = []
    options.command = 'decrypt'
    setCommandArgs(options, args)
    return this._gpg(args).promisify(options.stdin)
  }

  async editKey (options) {
    var args = []
    options.command = 'edit-key'
    setCommandArgs(options, args)
    return new Promise((resolve, reject) => {
      var s = this._gpg(args, { stdio: ['pipe', 'pipe', 'ignore'] })
      options.stdin.pipe(s.stdin)
      s.stdout.setEncoding('utf-8')
      //s.stderr.setEncoding('utf-8')
      s.stdout.on('end', e => {
        resolve()
      })
    })
  }

  async signKey (options) {
    var args = []
    options.command = 'sign-key'
    setCommandArgs(options, args)
    return this._gpg(args).promisify(options.stdin)
  }
}

export default GnuPGKeyring
