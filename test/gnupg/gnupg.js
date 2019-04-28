import assert from '../../../assert/assert.js'
import { homedir } from '../../../os/os.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
import { createGnuPG } from '../../gnupg/gnupg.js'
import { finishTest } from '../../../iso-test/index.js'
global.process = Process.getProcess()

const GnuPG = createGnuPG()
assert(GnuPG)
finishTest('pass GnuPG from Object')

const gnuPG = new GnuPG()
assert(gnuPG)
finishTest('pass create new GnuPG')

assert(gnuPG.home)
finishTest('pass gnuPG.home')

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
