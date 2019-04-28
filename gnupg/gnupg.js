import { homedir } from '../../os/os.js'
import { path } from '../../path/path.js'
import global from '../../global/global.js'
import { Process } from '../../process/process.js'
global.process = Process.getProcess()

export function createGnuPG (superclass) {
  superclass = superclass || Object
  return class GnuPG extends superclass {
    constructor (options) {
      options = options || {}
      super(options)
    }

    /*
     * Configuration helpers
     */
    get home () {
      // get cached GnuPG HOME
      if (typeof process.env.GNUPGHOME === 'undefined') {
        // set with default
        this.home = undefined
      }
      return process.env.GNUPGHOME
    }

    set home (h) {
      // set GnuPG HOME
      // defaults to $HOME/.gnupg
      h = h || path.join(homedir(), '.gnupg')
      process.env.GNUPGHOME = h
    }
  }
}

export default createGnuPG
