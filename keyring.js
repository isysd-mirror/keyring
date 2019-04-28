export function keyIdRe (len, flags) {
  return new RegExp(`[A-Z0-9]{${len}}`, flags)
}

export class Keyring {
  constructor (options) {
    this._config = options.config
  }
}

export default Keyring
