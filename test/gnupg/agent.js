import assert from '../../../assert/assert.js'
import { homedir } from '../../../os/os.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
import { GnuPGAgent } from '../../gnupg/agent.js'
import { createGnuPG } from '../../gnupg/gnupg.js'
import { finishTest } from '../../../iso-test/index.js'
import { setup } from './setup.js'
import { cleanup } from './cleanup.js'
global.process = Process.getProcess()
setup()

try {
  const agent = new GnuPGAgent()
  assert(agent)
  finishTest('pass create new GnuPGAgent')

  assert(agent.home)
  finishTest('pass agent.home')

  agent.home = 'newhome'
  assert(agent.home === 'newhome')
  finishTest('pass agent.home = newhome')

  assert(agent.getConfig)
  finishTest('pass agent.getConfig')

  cleanup()
  finishTest('kill')
} catch (e) {
  cleanup()
  finishTest(e)
}
