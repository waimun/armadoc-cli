import { describe, expect, it } from 'vitest'
import { ConfigError, configDir, downloadDir, onStage, resolveStage } from './config.js'

const HOME = '/home/ada'

describe('resolveStage', () => {
  it('defaults to prod', () => {
    expect(resolveStage({})).toEqual({
      stage: 'prod',
      apiBase: 'https://api.armadoc.link/v1',
      webOrigin: 'https://armadoc.link'
    })
  })

  it('derives the dev hostnames', () => {
    expect(resolveStage({ ARMADOC_STAGE: 'dev' })).toEqual({
      stage: 'dev',
      apiBase: 'https://api-dev.armadoc.link/v1',
      webOrigin: 'https://dev.armadoc.link'
    })
  })

  it('refuses a stage it does not know', () => {
    expect(() => resolveStage({ ARMADOC_STAGE: 'staging' })).toThrow(ConfigError)
  })
})

describe('onStage', () => {
  it('names only a stage other than prod', () => {
    expect(onStage('prod', 'to')).toBe('')
    expect(onStage('dev', 'to')).toBe(' to dev')
  })
})

describe('configDir', () => {
  it('keeps each stage in its own directory under ~/.config/armadoc', () => {
    expect(configDir({}, 'prod', HOME)).toBe('/home/ada/.config/armadoc/prod')
    expect(configDir({}, 'dev', HOME)).toBe('/home/ada/.config/armadoc/dev')
  })

  it('follows an absolute XDG_CONFIG_HOME and ignores a relative one', () => {
    expect(configDir({ XDG_CONFIG_HOME: '/xdg' }, 'prod', HOME)).toBe('/xdg/armadoc/prod')
    expect(configDir({ XDG_CONFIG_HOME: 'xdg' }, 'prod', HOME)).toBe(
      '/home/ada/.config/armadoc/prod'
    )
  })

  it('puts ARMADOC_HOME ahead of XDG and expands ~', () => {
    expect(configDir({ ARMADOC_HOME: '/tmp/a', XDG_CONFIG_HOME: '/xdg' }, 'dev', HOME)).toBe(
      '/tmp/a/dev'
    )
    expect(configDir({ ARMADOC_HOME: '~/.armadoc' }, 'dev', HOME)).toBe('/home/ada/.armadoc/dev')
  })

  it('refuses a relative ARMADOC_HOME', () => {
    expect(() => configDir({ ARMADOC_HOME: 'armadoc' }, 'prod', HOME)).toThrow(ConfigError)
  })
})

describe('downloadDir', () => {
  it('files each link under ~/Downloads/armadoc by default', () => {
    expect(downloadDir({}, { linkId: 'L1' }, HOME)).toBe('/home/ada/Downloads/armadoc/L1')
  })

  it('follows XDG_DOWNLOAD_DIR when it is set', () => {
    expect(downloadDir({ XDG_DOWNLOAD_DIR: '/dl' }, { linkId: 'L1' }, HOME)).toBe('/dl/armadoc/L1')
  })

  it('puts ARMADOC_DOWNLOAD_DIR ahead of XDG and expands ~', () => {
    const env = { ARMADOC_DOWNLOAD_DIR: '~/secure', XDG_DOWNLOAD_DIR: '/dl' }
    expect(downloadDir(env, { linkId: 'L1' }, HOME)).toBe('/home/ada/secure/L1')
  })

  it('writes straight into a directory the caller names', () => {
    expect(downloadDir({}, { linkId: 'L1', directory: '~/Desktop' }, HOME)).toBe(
      '/home/ada/Desktop'
    )
    expect(downloadDir({}, { linkId: 'L1', directory: '/srv/in' }, HOME)).toBe('/srv/in')
  })

  it('refuses a relative directory', () => {
    expect(() => downloadDir({}, { linkId: 'L1', directory: 'Desktop' }, HOME)).toThrow(ConfigError)
    expect(() => downloadDir({ ARMADOC_DOWNLOAD_DIR: 'dl' }, { linkId: 'L1' }, HOME)).toThrow(
      ConfigError
    )
  })
})
