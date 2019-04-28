import assert from '../../../assert/assert.js'
import global from '../../../global/global.js'
import { hostname } from '../../../os/os.js'
import { Process } from '../../../process/process.js'
import { setCommandArgs, GnuPGKeyring } from '../../gnupg/commands.js'
import { finishTest } from '../../../iso-test/index.js'
global.process = Process.getProcess()

var options = {}
var result = ''
gpgKeygenStream(options)
options.stdin.on('data', data => {
  result = result + data
})
options.stdin.on('finish', e => {
  assert(result.endsWith(`%commit
`))
  assert(result.indexOf(`Name-Real: ${process.env.USER}`) !== 1)
  assert(result.indexOf(`Name-Email: ${process.env.USER}@${hostname()}`) !== 1)
  assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
  assert(result.indexOf(`Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
`) !== 1)
  assert(result)
  finishTest('pass gpgKeygenStream default')
})

options = {
  'Key-Type': 'RSA'
}
result = ''
gpgKeygenStream(options)
options.stdin.on('data', data => {
  result = result + data
})
options.stdin.on('finish', e => {
  assert(result.endsWith(`%commit
`))
  assert(result.indexOf(`Name-Real: ${process.env.USER}`) !== 1)
  assert(result.indexOf(`Name-Email: ${process.env.USER}@${hostname()}`) !== 1)
  assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
  assert(result.indexOf(`Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
`) !== 1)
  assert(result)
  finishTest('pass gpgKeygenStream rsa')
})

options = {
  user: 'user',
  email: 'user@email',
  password: 'password'
}
result = ''
gpgKeygenStream(options)
options.stdin.on('data', data => {
  result = result + data
})
options.stdin.on('finish', e => {
  console.log(result)

  assert(result.endsWith(`%commit
`))
  assert(result.indexOf(`Passphrase: password`) !== 1)
  assert(result.indexOf(`Name-Real: user`) !== 1)
  assert(result.indexOf(`Name-Email: user@email`) !== 1)
  assert(result.indexOf(`Creation-Date: seconds=1`) !== 1)
  assert(result.indexOf(`Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
`) !== 1)
  assert(result)
  finishTest('pass gpgKeygenStream user pass')
})

options = { 'command': 'generate' }
var args = []
setCommandArgs(options, args)
assert(options.command === 'generate')
assert(args.join(' ') === '--yes --batch --generate-key')

options = { 'command': 'delete', 'keys': 'keys' }
args = []
setCommandArgs(options, args)
assert(options.command === 'delete')
assert(args.join(' ') === '--yes --batch --delete-keys keys')

options = { 'command': 'delete-secret', 'keys': 'keys' }
args = []
setCommandArgs(options, args)
assert(options.command === 'delete-secret')
assert(args.join(' ') === '--yes --batch --delete-secret-keys keys')

options = { 'command': 'list' }
args = []
setCommandArgs(options, args)
assert(options.command === 'list')
assert(args.join(' ') === '--list-keys --with-colons')

options = { 'command': 'list-secret' }
args = []
setCommandArgs(options, args)
assert(options.command === 'list-secret')
assert(args.join(' ') === '--list-secret-keys --with-colons')

options = { 'command': 'import' }
args = []
setCommandArgs(options, args)
assert(options.command === 'import')
assert(args.join(' ') === '--import')

options = { 'command': 'import-secret' }
args = []
setCommandArgs(options, args)
assert(options.command === 'import-secret')
assert(args.join(' ') === '--import --allow-secret-key-import')

options = { 'command': 'sign' }
args = []
setCommandArgs(options, args)
assert(options.command === 'sign')
assert(args.join(' ') === '--clear-sign')

options = { 'command': 'detach-sign' }
args = []
setCommandArgs(options, args)
assert(options.command === 'detach-sign')
assert(args.join(' ') === '--detach-sign')

options = { 'command': 'encrypt' }
args = []
setCommandArgs(options, args)
assert(options.command === 'encrypt')
assert(args.join(' ') === '-e')

options = { 'command': 'decrypt' }
args = []
setCommandArgs(options, args)
assert(options.command === 'decrypt')
assert(args.join(' ') === '-d')

options = { 'command': 'verify' }
args = []
setCommandArgs(options, args)
console.log(args.join(' '))
assert(options.command === 'verify')
assert(args.join(' ') === '--verify')
