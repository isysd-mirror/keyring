import { TRUST_LEVEL_ARRAY } from '../keyring.js'

export function noop (r, enc, cb) {
  r = r.toString(this.encoding || 'utf-8')
  this.push(r)
  cb()
}

export function fprUidReducer (da, enc, cb) {
  var matched
  var self = this
  self.strcache = self.strcache || ''
  self.strcache = self.strcache + da.toString('utf-8')
  while (matched = /fpr[:]*[A-Z0-9]{40}/g.exec(this.strcache)) {
    var fpr2 = matched[0].replace(/fpr[:]*/, '')
    var uida = /[A-Z0-9]{40}::[^:]+/.exec(self.strcache)
    if (uida) {
      var uid = uida[0].split(':')
      uid = uid.slice(-1)[0]
      self.strcache = self.strcache.slice(uida.index + uida.length)
      self.push(`${fpr2}::${uid}`)
    }
    // else keys[fpr2] = keys[fpr2]
  }
  cb()
}

export function colonListReducer (da, enc, cb) {
  var matched
  var self = this
  self.strcache = self.strcache || ''
  self.strcache = (self.strcache + da.toString('utf-8')).replace(/grp:*[A-Z0-9]*:*\n*/, '')
  while (matched = /fpr.*[\n]+(grp:*[A-Z0-9]*\n)*.*uid.*::::::::::/mg.exec(this.strcache)) {
    self.push(matched[0])
    self.strcache = self.strcache.slice(matched.index + matched[0].length)
  }
  cb()
}

export function secretKeyImportReducer (da, enc, cb) {
  var self = this
  self.strcache = self.strcache || ''
  self.strcache = self.strcache + da.toString('utf-8')
  da = da.match(/sec.*[\n]+.*[A-Z0-9]{40}.*[\n]*.*[\n]*.*uid.*::::::::::/g)
  if (da) da.forEach(this.push)
  cb()
}

export function keyTrustedReducer (chunk, enc, cb) {
  var matched
  var self = this
  self.strcache = self.strcache || ''
  self.strcache = self.strcache + chunk.toString('utf-8')
  while (matched = /key [A-Zx0-9]{16,40} marked as [a-z]{4,20} trusted/.exec(this.strcache)) {
    var keyid = /[A-Zx0-9]{16,40}/.exec(matched[0])
    if (keyid) {
      self.push(keyid[0])
      self.strcache = self.strcache.slice(matched.index + matched[0].length)
    }
  }
  cb()
}

export function verifySigReducer (chunk, enc, cb) {
  var matched
  var self = this
  self.strcache = self.strcache && self.strcache.length > 0 ? self.strcache : ''
  self.sig = {}
  if (enc !== 'utf-8') chunk = chunk.toString('utf-8')
  var siga = `${self.strcache}\n${chunk}`.replace('\n\n', '\n').split('\n')
  var s
  while (s = siga.shift()) {
    if (s.length === 0 || s === '[GNUPG:] NEWSIG') continue
    // else if (s.startsWith('[GNUPG:] KEY_CONSIDERED ')) sig.keys_considered = s.slice(24, s.length-3)
    else if (s.startsWith('[GNUPG:] VALIDSIG ')) {
      self.sig.sigkey = s.slice(18, 58)
      self.sig.key = s.slice(s.length - 40)
      self.sig.timestamp = parseInt(s.slice(70).match(/^[0-9]*/)[0])
    } else if (s.startsWith('[GNUPG:] GOODSIG ')) {
      self.sig.good = s.slice(17).match(/^[A-F0-9]{16,40}/)[0]
      self.sig.uid = s.slice(17 + self.sig.good.length + 1).trim(' ')
    } else if (s.startsWith('[GNUPG:] TRUST_')) {
      self.sig.trust = TRUST_LEVEL_ARRAY.indexOf(s.slice(15).match(/[A-Z]*/)[0].toLowerCase()) + 1
    }
  }
  if (chunk.join) chunk = chunk.join('\n')
  if (self.sig.hasOwnProperty('trust') && self.sig.trust >= 0 && self.sig.sigkey && self.sig.key && self.sig.timestamp && self.sig.good && self.sig.uid) {
    self.push([self.sig.sigkey, self.sig.key, self.sig.timestamp, self.sig.trust, self.sig.uid].join(' '))
    //process.stdout.write(self.strcache + "\n" + chunk + "\n")
    self.strcache = ''
    self.sig = {}
  } else {
    self.strcache = `${self.strcache}${chunk}`.replace('\n\n', '\n')
  }
  cb()
}

export default {
  noop,
  fprUidReducer,
  colonListReducer,
  secretKeyImportReducer,
  keyTrustedReducer,
  verifySigReducer
}
