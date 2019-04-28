import assert from '../../../assert/assert.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
import { senseGpgExec, senseGpgAgentExec } from '../../gnupg/executables.js'
import { finishTest } from '../../../iso-test/index.js'
global.process = Process.getProcess()
process.env.GNUPG_EXEC = null
process.env.GNUPG_AGENT_EXEC = null

senseGpgExec()
assert(process.env.GNUPG_EXEC)
finishTest('pass senseGpgExec')

senseGpgAgentExec()
assert(process.env.GNUPG_AGENT_EXEC)
finishTest('pass senseGpgAgentExec')
