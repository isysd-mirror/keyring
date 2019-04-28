
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

export default {
  noop,
  fprUidReducer,
  colonListReducer,
  secretKeyImportReducer,
  keyTrustedReducer
}
