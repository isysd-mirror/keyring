import { fs } from '../../../fs/fs.js'
import { path } from '../../../path/path.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
global.process = Process.getProcess()

process.env.GNUPGHOME = path.resolve('./test/gnupg/home')
delete process.env.GNUPG_EXEC
delete process.env.GNUPG_AGENT_EXEC

export function setup () {
  fs.mkdirSync(path.resolve('./test/gnupg/home'), {
    recursive: true,
    mode: 0o700
  })
  var file = fs.readFileSync(path.resolve('./fixtures/file.txt'))
  var gpg = fs.readFileSync(path.resolve('./fixtures/gpg.conf'))
  var agent = fs.readFileSync(path.resolve('./fixtures/gpg-agent.conf'))
  var keygen = fs.readFileSync(path.resolve('./fixtures/keygen.conf'))
  fs.writeFileSync(path.join(process.env.GNUPGHOME, 'file.txt'), file)
  fs.writeFileSync(path.join(process.env.GNUPGHOME, 'gpg.conf'), gpg)
  fs.writeFileSync(path.join(process.env.GNUPGHOME, 'gpg-agent.conf'), agent)
  fs.writeFileSync(path.join(process.env.GNUPGHOME, 'keygen.conf'), keygen)
}

export default setup
