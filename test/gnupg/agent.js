import assert from '../../../assert/assert.js'
import { homedir } from '../../../os/os.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
import { GnuPGAgent } from '../../gnupg/agent.js'
import { createGnuPG } from '../../gnupg/gnupg.js'
import { finishTest } from '../../../iso-test/index.js'
global.process = Process.getProcess()

const agent = new GnuPGAgent()
assert(agent)
finishTest('pass create new GnuPGAgent')

assert(agent.home)
finishTest('pass agent.home')

gnuPG.home = 'newhome'
assert(gnuPG.home === 'newhome')
finishTest('pass gnuPG.home = newhome')

class MyClass {
  myfunction () {
  }
}

const MyGnuPG = createGnuPG(MyClass)
assert(MyGnuPG)
finishTest('pass MyGnuPG from MyClass')

assert(MyGnuPG)
finishTest('pass GnuPG from Object')

const mygnuPG = new MyGnuPG()
assert(mygnuPG)
finishTest('pass create new MyGnuPG')

assert(mygnuPG.home)
finishTest('pass mygnuPG.home')

assert(mygnuPG.myfunction)
finishTest('pass mygnuPG.myfunction')

finishTest('kill')
