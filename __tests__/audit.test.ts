import * as child_process from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import {Audit} from '../src/audit'

jest.mock('child_process')

const audit = new Audit()

describe('run', () => {
  beforeEach(() => {
    jest.mocked(child_process).spawnSync.mockClear()
  })

  test('finds vulnerabilities with default values', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      const stdout = fs.readFileSync(
        path.join(__dirname, 'testdata/audit/error.txt')
      )

      return {
        pid: 100,
        output: [stdout],
        stdout,
        stderr: '',
        status: 1,
        signal: null,
        error: null
      }
    })

    audit.run('low', 'false', 'false', 'true')
    expect(audit.foundVulnerability()).toBeTruthy()
  })

  test('finds vulnerabilities with production flag enabled', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      const stdout = fs.readFileSync(
        path.join(__dirname, 'testdata/audit/error.txt')
      )

      return {
        pid: 100,
        output: [stdout],
        stdout,
        stderr: '',
        status: 1,
        signal: null,
        error: null
      }
    })

    audit.run('low', 'true', 'false', 'true')
    expect(audit.foundVulnerability()).toBeTruthy()
  })

  test('finds vulnerabilities with json flag enabled', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      const stdout = fs.readFileSync(
        path.join(__dirname, 'testdata/audit/error.json')
      )

      return {
        pid: 100,
        output: [stdout],
        stdout,
        stderr: '',
        status: 1,
        signal: null,
        error: null
      }
    })

    audit.run('low', 'false', 'true', 'true')
    expect(audit.foundVulnerability()).toBeTruthy()
  })

  test('does not find vulnerabilities', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      const stdout = fs.readFileSync(
        path.join(__dirname, 'testdata/audit/success.txt')
      )

      return {
        pid: 100,
        output: [stdout],
        stdout,
        stderr: '',
        status: 0,
        signal: null,
        error: null
      }
    })

    audit.run('low', 'false', 'false', 'false')
    expect(audit.foundVulnerability()).toBeFalsy()
  })

  test('throws an error if error is not null', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      return {
        pid: 100,
        output: '',
        stdout: '',
        stderr: '',
        status: 0,
        signal: null,
        error: new Error('Something is wrong')
      }
    })

    expect.assertions(1)
    const e = new Error('Something is wrong')
    expect(() => audit.run('low', 'false', 'false', 'true')).toThrowError(e)
  })

  test('throws an error if status is null', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      return {
        pid: 100,
        output: '',
        stdout: '',
        stderr: '',
        status: null,
        signal: 'SIGTERM',
        error: null
      }
    })

    expect.assertions(1)
    const e = new Error('the subprocess terminated due to a signal.')
    expect(() => audit.run('low', 'false', 'false', 'true')).toThrowError(e)
  })

  test('throws an error if stderr is null', () => {
    jest.mocked(child_process).spawnSync.mockImplementation((): any => {
      return {
        pid: 100,
        output: '',
        stdout: '',
        stderr: 'Something is wrong',
        status: 1,
        signal: null,
        error: null
      }
    })

    expect.assertions(1)
    const e = new Error('Something is wrong')
    expect(() => audit.run('low', 'false', 'false', 'true')).toThrowError(e)
  })
})
