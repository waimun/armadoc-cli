import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'

const ROOT_DOMAIN = 'armadoc.link'
const STAGES = ['prod', 'dev']

export class ConfigError extends Error {}

export const resolveStage = (env) => {
  const stage = env.ARMADOC_STAGE || 'prod'
  if (!STAGES.includes(stage)) {
    throw new ConfigError(`ARMADOC_STAGE must be one of ${STAGES.join(', ')}`)
  }

  const prod = stage === 'prod'
  return {
    stage,
    apiBase: `https://${prod ? 'api' : `api-${stage}`}.${ROOT_DOMAIN}/v1`,
    webOrigin: `https://${prod ? '' : `${stage}.`}${ROOT_DOMAIN}`
  }
}

export const onStage = (stage, preposition) => (stage === 'prod' ? '' : ` ${preposition} ${stage}`)

const xdgDir = (value, fallback) => (value && isAbsolute(value) ? value : fallback)

const expandHome = (path, home) =>
  path === '~' || path.startsWith('~/') ? join(home, path.slice(1)) : path

const absolute = (path, name) => {
  if (!isAbsolute(path)) throw new ConfigError(`${name} must be an absolute path`)
  return path
}

export const configDir = (env, stage, home = homedir()) => {
  const root = env.ARMADOC_HOME
    ? absolute(expandHome(env.ARMADOC_HOME, home), 'ARMADOC_HOME')
    : join(xdgDir(env.XDG_CONFIG_HOME, join(home, '.config')), 'armadoc')
  return join(root, stage)
}

export const downloadDir = (env, { linkId, directory }, home = homedir()) => {
  if (directory !== undefined) return absolute(expandHome(directory, home), 'directory')

  const base = env.ARMADOC_DOWNLOAD_DIR
    ? absolute(expandHome(env.ARMADOC_DOWNLOAD_DIR, home), 'ARMADOC_DOWNLOAD_DIR')
    : join(xdgDir(env.XDG_DOWNLOAD_DIR, join(home, 'Downloads')), 'armadoc')
  return join(base, linkId)
}
