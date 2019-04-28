import global from '../../global/global.js'
import { Process } from '../../process/process.js'
import child_process from '../../child_process/child_process.js'
import fs from '../../fs/fs.js'
import path from '../../path/path.js'
import { createGnuPG } from './gnupg.js'
import { senseGpgAgentExec } from './executables.js'
global.process = Process.getProcess()

export class GnuPGAgent extends createGnuPG() {
  async init () {
    process.env.GNUPG_AGENT_EXEC = await senseGpgAgentExec().catch(e => undefined)
  }

  get __agent () {
    // the cached path to GnuPG Agent executable
    return process.env.GNUPG_AGENT_EXEC
  }

  _gpgAgent (args, options) {
    if (this.__agent) {
      options = options || {}
      options.windowsHide = true
      options.env = process.env
      return child_process.spawn(this.__agent, args, options)
    }
  }

  async setAgentCache (seconds) {
    var body
    if (seconds) {
      body = `default-cache-ttl ${seconds}\n`
    } else {
      body = ''
    }
    await fs.promises.writeFile(path.join(this.home, 'gpg-agent.conf'), body)
  }

  /*
   * Agent management API
   */
  async isLocked (keygrip) {
    const stdout = await this._gpgAgent().promisify(`KEYINFO --no-ask ${keygrip} Err Pmt Des`)
    return !gpgAgentRe(keygrip).test(stdout)
  }

  async reload () {
    await this._gpgAgent(['reloadagent', '/bye']).promisify()
  }

  async kill () {
    await this._gpgAgent(['kill', '/bye']).promisify()
  }
}

export function gpgAgentRe (grip) {
  return new RegExp(`^S KEYINFO ${grip} [DP1 -]{0,20}\nOK\n*$`)
}

export default GnuPGAgent
