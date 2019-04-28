import assert from '../../../assert/assert.js'
import { finishTest } from '../../../iso-test/index.js'
import { expandConfig, flattenConfig, createGnuPGConfig } from '../../gnupg/config.js'
import { path } from '../../../path/path.js'
import fs from '../../../fs/fs.js'
// this is relative to keyring project root, not module directory
// no __dirname available in es6!
process.env.GNUPGHOME = path.resolve('./fixtures')
const GnuPGConfig = createGnuPGConfig()
var gnuPGConfig = new GnuPGConfig()
var confile
var conf
var flat
assert(gnuPGConfig)
assert(gnuPGConfig.writeConfigFile)
assert(gnuPGConfig.initConfig)
assert(gnuPGConfig.getConfig)
assert(gnuPGConfig.setConfig)

new Promise(async (resolve, reject) => {
  confile = await fs.promises.readFile(path.join(process.env.GNUPGHOME, 'gpg.conf'), 'utf-8')
  conf = expandConfig(confile.split('\n'))
  assert(conf)
  assert(conf['no-greeting'])
  assert(conf['no-auto-key-locate'])
  assert(conf['no-auto-key-locate'].comments === '# Don\'t leak information by automatically trying to get keys.\n')
  assert(JSON.stringify(['S9', 'S8', 'S7', 'S10', 'S4', 'S13', 'S12', 'S11']) === JSON.stringify(conf['personal-cipher-preferences'].args))
  flat = flattenConfig(conf)
  // used to generate the fixture
  // await gnuPGConfig.writeConfigFile(flat)
  assert(flat)
  assert.equal(confile.replace('\n', ''), flat.replace('\n', ''))

  // legacy test code never been enabled
  /*
  var islocked = await gpg.isLocked(fpr)
  assert.isNotTrue(islocked)
  await gpg.lockKey(fpr, 'password')
  var islocked = await gpg.isLocked(fpr)
  assert.isTrue(islocked)
  await gpg.unlockKey(fpr, 'password')
  var islocked = await gpg.isLocked(fpr)
  assert.exists(islocked)
  assert.isNotTrue(islocked)
  */
}).catch(e => {
  console.error(e)
  finishTest(e)
})
