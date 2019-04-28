import global from '../../global/global.js'
import { fs } from '../../fs/fs.js'
import { path } from '../../path/path.js'
import { child_process } from '../../child_process/child_process.js'
import { Process } from '../../process/process.js'
global.process = Process.getProcess()

/*
 * GPG environment discovery
 */
export async function senseGpgExec () {
  // look for process.env.GNUPG_EXEC
  if (process.env.GNUPG_EXEC) return process.env.GNUPG_EXEC
  else {
    // try to spawn gpg2
    process.env.GNUPG_EXEC = process.env.GNUPG_EXEC || await child_process.spawn('gpg2', ['--version']).promisify().then(d => d && d.length > 0 ? 'gpg2' : undefined).catch(e => undefined)
    // try to spawn gpg
    process.env.GNUPG_EXEC = process.env.GNUPG_EXEC || await child_process.spawn('gpg', ['--version']).promisify().then(d => d && d.length > 0 ? 'gpg' : undefined).catch(e => undefined)
    // try git config gpg.program
    process.env.GNUPG_EXEC = process.env.GNUPG_EXEC || await child_process.spawn('git', ['--config', 'gpg.program']).promisify().then(d => d && d.length > 0 ? d.replace(/[\n\r]*$/, '') : undefined).catch(e => undefined)
    // return if set...
    if (process.env.GNUPG_EXEC) return process.env.GNUPG_EXEC
    // try to guess path based on platform
    if (process.platform === 'win32') {
      var pathroot = path.win32.parse(path.win32.normalize('file.ext')).root
      var stats = await fs.promises.stat(path.join(
        pathroot,
        'Program Files',
        'Gpg4win'
      )).catch(e => null)
      if (stats && stats.isDirectory()) {
        process.env.GNUPG_EXEC = path.join(
          pathroot,
          'Program Files',
          'Gpg4win',
          'bin',
          'gpg.exe' // TODO is this correct file name?
        )
        return process.env.GNUPG_EXEC
      }
      stats = await fs.promises.stat(path.join(
        pathroot,
        'Program Files',
        'GNU',
        'GnuPG',
        'gpg.exe' // TODO is this correct file name?
      )).catch(e => null)
      if (stats && stats.isDirectory()) {
        process.env.GNUPG_EXEC = path.join(
          pathroot,
          'Program Files',
          'GNU',
          'GnuPG',
          'gpg.exe' // TODO is this correct file name?
        )
        return process.env.GNUPG_EXEC
      }
      stats = await fs.promises.stat(path.join(
        pathroot,
        'Program Files',
        'GNU',
        'bin',
        'gpg.exe' // TODO is this correct file name?
      )).catch(e => null)
      if (stats && stats.isDirectory()) {
        process.env.GNUPG_EXEC = path.join(
          pathroot,
          'Program Files',
          'GNU',
          'bin',
          'gpg.exe' // TODO is this correct file name?
        )
        return process.env.GNUPG_EXEC
      }
    } else if (process.platform === 'darwin') {
      // TODO guess mac paths that wouldn't already be in PATH...
      // guess /usr/local/MacGPG2/bin/gpg2
    } else {
      // TODO guess linux paths that wouldn't already be in PATH...
    }
  }
  // throw error since unable to sense
  throw new Error('Could not find gpg executable.')
}

export async function senseGpgAgentExec () {
  // look for process.env.GNUPG_AGENT_EXEC
  if (process.env.GNUPG_AGENT_EXEC) return process.env.GNUPG_AGENT_EXEC
  else {
    // try to spawn gpg-connect-agent
    process.env.GNUPG_AGENT_EXEC = process.env.GNUPG_AGENT_EXEC || await child_process.spawn('gpg-connect-agent', ['--version']).promisify().then(d => d && d.length > 0 ? 'gpg-connect-agent' : undefined).catch(e => undefined)
    // return if set...
    if (process.env.GNUPG_AGENT_EXEC) return process.env.GNUPG_AGENT_EXEC
    // try to guess path based on platform
    if (process.platform === 'win32') {
      // TODO guess win32 paths that wouldn't already be in PATH...
    } else if (process.platform === 'darwin') {
      // TODO guess mac paths that wouldn't already be in PATH...
    } else {
      // TODO guess linux paths that wouldn't already be in PATH...
    }
  }
  // throw error since unable to sense
  throw new Error('Could not find gpg agent executable.')
}

export default {
  senseGpgAgentExec,
  senseGpgExec
}
