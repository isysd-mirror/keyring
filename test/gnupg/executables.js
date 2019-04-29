import assert from '../../../assert/assert.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
import { senseGpgExec, senseGpgAgentExec } from '../../gnupg/executables.js'
import { finishTest } from '../../../iso-test/index.js'
import { setup } from './setup.js'
import { cleanup } from './cleanup.js'
global.process = Process.getProcess()
setup()

new Promise(async (resolve, reject) => {
  await senseGpgExec()
  assert(typeof process.env.GNUPG_EXEC === 'string')
  finishTest('pass senseGpgExec')
  await senseGpgAgentExec()
  assert.ok(process.env.GNUPG_AGENT_EXEC)
  assert(typeof process.env.GNUPG_AGENT_EXEC === 'string')
  finishTest('pass senseGpgAgentExec')
  cleanup()
  finishTest('kill')
}).catch(e => {
  console.error(e)
  cleanup()
  finishTest(e)
})
