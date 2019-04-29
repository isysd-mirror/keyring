import assert from '../../../assert/assert.js'
import global from '../../../global/global.js'
import { hostname } from '../../../os/os.js'
import { Process } from '../../../process/process.js'
import { setCommandArgs, GnuPGKeyring } from '../../gnupg/keyring.js'
import { finishTest } from '../../../iso-test/index.js'
import { setup } from './setup.js'
import { cleanup } from './cleanup.js'
global.process = Process.getProcess()
setup()

try {
  var options = { 'command': 'generate' }
  var args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'generate')
  assert.equal(args.join(' '), '--yes --batch --generate-key')
  finishTest('pass generate')

  options = { 'command': 'delete', 'keys': 'keys' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'delete')
  assert.equal(args.join(' '), '--yes --batch --delete-keys keys')
  finishTest('pass delete')

  options = { 'command': 'delete-secret', 'keys': 'keys' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'delete-secret')
  assert.equal(args.join(' '), '--yes --batch --delete-secret-and-public-key keys')
  finishTest('pass delete-secret')

  options = { 'command': 'list' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'list')
  assert.equal(args.join(' '), '--list-keys --with-colons')
  finishTest('pass list')

  options = { 'command': 'list-secret' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'list-secret')
  assert.equal(args.join(' '), '--list-secret-keys --with-colons')
  finishTest('pass list-secret')

  options = { 'command': 'import' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'import')
  assert.equal(args.join(' '), '--import')
  finishTest('pass import')

  options = { 'command': 'import-secret' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'import-secret')
  assert.equal(args.join(' '), '--import --allow-secret-key-import')
  finishTest('pass import-secret')

  options = { 'command': 'sign' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'sign')
  assert.equal(args.join(' '), '-o - --clear-sign')
  finishTest('pass sign')

  options = {
    'command': 'sign',
    'infile': './LICENSE'
  }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'sign')
  assert.equal(args.join(' '), '-o - --clear-sign ./LICENSE')
  finishTest('pass sign infile')

  options = {
    'command': 'sign',
    'outfile': './LICENSE.sig'
  }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'sign')
  assert.equal(args.join(' '), '-o ./LICENSE.sig --clear-sign')
  finishTest('pass sign outfile')

  options = { 'command': 'detach-sign' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'detach-sign')
  assert.equal(args.join(' '), '-o - --detach-sign')
  finishTest('pass detach-sign')

  /*options = {
    'command': 'detach-sign',
    'stdin': 'hello world'
  }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'detach-sign')
  assert.equal(args.join(' '), '-o - --detach-sign --status-fd=1')
  finishTest('pass detach-sign stdin')*/

  options = {
    'command': 'detach-sign',
    'infile': './LICENSE',
    'outfile': './LICENSE.sig' 
  }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'detach-sign')
  assert.equal(args.join(' '), '-o ./LICENSE.sig --detach-sign ./LICENSE')
  finishTest('pass detach-sign outfile')

  options = {
    'command': 'detach-sign',
    'infile': './LICENSE' 
  }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'detach-sign')
  assert.equal(args.join(' '), '-o - --detach-sign ./LICENSE')
  finishTest('pass detach-sign outfile')

  options = { 'command': 'encrypt' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'encrypt')
  assert.equal(args.join(' '), '-o - -e')
  finishTest('pass encrypt')

  options = { 'command': 'decrypt' }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'decrypt')
  assert.equal(args.join(' '), '-o - -d')
  finishTest('pass decrypt')

  options = { 'command': 'verify', stdin: true }
  args = []
  setCommandArgs(options, args)
  assert.equal(options.command, 'verify')
  assert.equal(args.join(' '), '--status-fd=1 --verify')
  finishTest('pass verify')

  cleanup()
  finishTest('kill')
} catch (e) {
  cleanup()
  finishTest(e)
}
