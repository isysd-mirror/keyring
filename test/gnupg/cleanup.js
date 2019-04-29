import { fs } from '../../../fs/fs.js'
import { path } from '../../../path/path.js'
import global from '../../../global/global.js'
import { Process } from '../../../process/process.js'
global.process = Process.getProcess()

process.env.GNUPGHOME = path.resolve('./test/gnupg/home')

export function cleanup () {
  return fs.rimrafSync(path.resolve('./test/gnupg/home'))
}

export default cleanup
