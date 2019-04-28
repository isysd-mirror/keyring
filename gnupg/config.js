import { createGnuPG } from './gnupg.js'
import { path } from '../../path/path.js'
import fs from '../../fs/fs.js'

/*
 * Securish defaults
 */
export const DEFAULTS = { 'no-greeting':
   { comments:
      '# source:\n# https://github.com/coruus/cooperpair/blob/master/saneprefs/gpg.conf\n',
   args: [] },
'no-auto-key-locate':
   { comments:
      "# Don't leak information by automatically trying to get keys.\n",
   args: [] },
charset:
   { comments:
      '# Set the charset to UTF-8; you should make sure that your terminal correctly implements UTF-8 support.\n# TODO(dlg): vttest?\n',
   args: [ 'utf-8' ] },
'display-charset': { comments: '\n', args: [ 'utf-8' ] },
'keyid-format':
   { comments: '# Display long keyids and fingerprints by default\n',
     args: [ '0xlong' ] },
'with-fingerprint': { comments: '\n', args: [] },
verbose: { comments: '\n', args: [] },
'list-options':
   { comments:
      '# Never show photos, but show all notations and signature subpackets\n',
   args:
      [ 'show-policy-urls',
        'no-show-photos',
        'show-notations',
        'show-keyserver-urls',
        'show-uid-validity',
        'show-sig-subpackets' ] },
'verify-options':
   { comments: '\n',
     args:
      [ 'show-policy-urls',
        'no-show-photos',
        'show-notations',
        'show-keyserver-urls',
        'show-uid-validity',
        'no-pka-lookups',
        'no-pka-trust-increase' ] },
'disable-dsa2':
   { comments:
      "# Disable truncating DSA2 message hashes (yes, that's what this does)\n",
   args: [] },
keyserver:
   { comments:
      '# Use the https-secured HKPS pool. The sks-keyservers.net CA is available at https://sks-keyservers.net/sks-keyservers.netCA.pem\n',
   args: [ 'hkps://hkps.pool.sks-keyservers.net' ] },
'keyserver-options':
   { comments: '\n',
     args:
      [ 'check-cert',
        'ca-cert-file=~/.gnupg/sks-keyservers.netCA.pem',
        'keep-temp-files',
        'verbose',
        'verbose',
        'debug',
        'no-honor-keyserver-url',
        'no-auto-key-retrieve',
        'no-honor-pka-record' ] },
'require-cross-certification':
   { comments: '# Some options to avoid stupid behaviors.\n',
     args: [] },
'force-v4-certs': { comments: '\n', args: [] },
'import-options':
   { comments: '\n',
     args: [ 'no-repair-pks-subkey-bug', 'import-clean' ] },
'export-options': { comments: '\n', args: [ 'export-clean' ] },
'force-mdc': { comments: '\n', args: [] },
's2k-cipher-algo':
   { comments:
      '# Use a real encryption algorithm to protect the secret keyring, rather than CAST5.\n',
   args: [ 'AES256' ] },
's2k-digest-algo': { comments: '\n', args: [ 'SHA512' ] },
's2k-mode': { comments: '\n', args: [ '3' ] },
's2k-count':
   { comments:
      "# This is the maximum iteration count. It's way too small. You should entomb or just\n# scrypt your private keyring when not in use.\n",
   args: [ '65011712' ] },
'personal-cipher-preferences':
   { comments:
      '# Human-readable version of cipher preferences:\n# Cipher: AES256, AES192, AES, TWOFISH, BLOWFISH, CAMELLIA256, CAMELLIA192, CAMELLIA128\n#   rationale: AES is best-studied. Twofish and Blowfish second-best. CAMELLIA is believed\n#   to be as strong as AES but much less studied. (You may prefer moving AES128 lower.)\n# Digest: SHA512, SHA384, SHA224, SHA256, RIPEMD160\n#   rationale: SHA2 is still considered strong. RIPEMD160 is believed better than SHA-1.\n# Compression: ZLIB, BZIP2, ZIP, Uncompressed\n#   rationale: Personal preference.\n\n# Set cipher preferences for encryption/signing to other users.\n# NB: This does not prevent an 3DES, IDEA, or MD5 from being used, if the recipient\n# prefers it.\n',
   args: [ 'S9', 'S8', 'S7', 'S10', 'S4', 'S13', 'S12', 'S11' ] },
'personal-digest-preferences':
   { comments: '\n',
     args: [ 'H10', 'H9', 'H11', 'H8', 'H3', 'H2' ] },
'personal-compress-preferences': { comments: '\n', args: [ 'Z2', 'Z3', 'Z1', 'Z0' ] },
'disable-cipher-algo': { comments: '\n', args: [ 'CAST5', 'IDEA' ] },
'default-preference-list':
   { comments:
      '# Regrettably, not supported by GnuPG\n# disable-digest-algo MD5\n\n# Set the default preference list for new keys.\n',
   args:
      [ 'S9',
        'S8',
        'S7',
        'S10',
        'S4',
        'S13',
        'S12',
        'S11',
        'H10',
        'H9',
        'H11',
        'H8',
        'H3',
        'H2',
        'Z2',
        'Z3',
        'Z1',
        'Z0' ] },
'Key-Type':
   { comments:
      '\n# Not GnuPG-standard! Guld keyring will try to enforce these, but it is not guaranteed.\n# List all acceptable key options from least preferable to most\n',
   args: [ 'RSA', 'ECC', 'eddsa' ] },
'Key-Length':
   { comments: '# Only active for RSA keys, ECC keys are 256 bit\n',
     args: [ '2048', '3072', '4096' ] },
'Key-Curve':
   { comments:
      '# Key-Usage is standardized by OpenPGP\n# Key-Usage sign cert\n# Only active for ECC eddsa ecdh keys\n',
   args: [ 'secp256k1', 'Curve25519', 'Ed25519' ] },
'Subkey-Type': { comments: '', args: [ 'RSA', 'ECC', 'eddsa', 'ecdh' ] },
'Subkey-Length':
   { comments: '# Only active for RSA keys, ECC keys are 256 bit\n',
     args: [ '2048', '3072', '4096' ] },
'Subkey-Curve':
   { comments: '# Only active for ECC eddsa ecdh keys\n',
     args: [ 'secp256k1', 'Ed25519', 'Curve25519' ] },
'Subkey-Usage': { comments: '', args: [ 'sign', 'auth', 'encrypt' ] }
}

export function createGnuPGConfig (superclass) {
  superclass = superclass || Object
  return class GnuPGConfig extends createGnuPG(superclass) {
    constructor (options) {
      options = options || {}
      super(options)
    }

    get config () {
      return this._config
    }

    async initConfig () {
      if (this._config) return
      try {
        await this.getConfig()
        this.setConfigDefaults()
      } catch (e) {
        if (process.env.DEBUG) process.stdout.write(e.toString() + '\n')
        await this.writeConfig(DEFAULTS)
      }
    }

    async getConfig () {
      var p = path.join(this.home, 'gpg.conf')
      var lines = await fs.promises.readFile(p, 'utf-8')
      this._config = expandConfig(lines.split('\n'))
      return this._config
    }

    async setConfig (key, vals = [], comments = '') {
      var p = path.join(this.home, 'gpg.conf')
      var lines = await fs.promises.readFile(p, 'utf-8')
      var re = `[#]*${key}.*[\n]+`
      lines = lines.replace(new RegExp(re), '').split('\n')
      this._config = expandConfig(lines)
      this.config[key] = {
        comments: comments || '',
        args: vals || []
      }
      return this.writeConfigFile(flattenConfig(this.config))
    }

    async writeConfigFile (contents) {
      return fs.promises.writeFile(path.join(this.home, 'gpg.conf'), contents)
    }

    async setConfigDefaults () {
      DEFAULTS.forEach(d => {
        this.config[d] = DEFAULTS[d]
      })
      return this.writeConfigFile(flattenConfig(this.config))
    }

    /*
    async setDefaultKey (fpr) {
      await this.setConfig('default-key', [fpr])
    }
    */
  }
}

/*
 * GPG Configuration file manipulation
 */
export function expandConfig (lines) {
  var comments = ''
  var conf = {}
  for (var l in lines) {
    if (lines[l].length <= 1 || lines[l].startsWith('#')) comments = `${comments}${lines[l]}\n`
    else {
      var words = lines[l].split(' ')
      var cmd = words.shift()
      conf[cmd] = {
        'comments': comments,
        'args': words
      }
      comments = ''
    }
  }
  return conf
}

export function flattenConfig (conf) {
  var lines = ''
  Object.keys(conf).forEach(o => {
    lines = `${lines.trim()}\n${conf[o].comments.trim()}\n${o} ${conf[o].args.join(' ')}\n`
  })
  return lines
}

export default {
  DEFAULTS,
  expandConfig,
  flattenConfig,
  createGnuPGConfig
}
