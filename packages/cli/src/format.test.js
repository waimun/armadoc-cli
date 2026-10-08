import { describe, expect, it } from 'vitest'
import { describeList, describeRead, describeSend } from './format.js'

const EMPTY = { awaitingAcceptance: [], awaitingUpload: [], active: [] }
const EXPIRES = '2026-10-17T14:05:09.000Z'

describe('describeList', () => {
  it('groups the open rows by direction and stage, skipping empty ones', () => {
    const data = {
      inbound: {
        ...EMPTY,
        active: [
          { linkId: 'L1', senderName: 'Ada', fileNames: ['a.pdf', 'b.txt'], expiresAt: EXPIRES }
        ]
      },
      outbound: {
        ...EMPTY,
        awaitingUpload: [
          {
            inviteId: 'I1',
            recipientName: 'Grace',
            recipientEmail: 'grace@example.test',
            fileNames: ['c.pdf'],
            expiresAt: EXPIRES
          }
        ]
      }
    }

    expect(describeList(data)).toBe(
      [
        'Sent to you:',
        '  L1  from Ada: a.pdf, b.txt, until 2026-10-17 14:05 UTC',
        '',
        'Invites accepted; send the same files to complete them:',
        '  to Grace <grace@example.test>: c.pdf, until 2026-10-17 14:05 UTC'
      ].join('\n')
    )
  })

  it('says when nothing is open, in one direction or both', () => {
    expect(describeList({ inbound: EMPTY, outbound: EMPTY })).toBe('Nothing is open.')
    expect(describeList({ outbound: EMPTY })).toBe('Nothing is open.')
  })
})

describe('describeRead', () => {
  it('lists the saved files with their sizes', () => {
    const data = {
      linkId: 'L1',
      directory: '/tmp/out',
      files: [
        { name: 'a.txt', path: '/tmp/out/a.txt', size: 12 },
        { name: 'b.pdf', path: '/tmp/out/b.pdf', size: 2_621_440 }
      ]
    }

    expect(describeRead(data)).toBe('Saved to /tmp/out:\n  a.txt (12 B)\n  b.pdf (2.5 MB)')
  })
})

describe('describeSend', () => {
  const recipient = { name: 'Grace', email: 'grace@example.test' }

  it('names the files, the recipient and the expiry', () => {
    expect(
      describeSend({
        status: 'sent',
        linkId: 'L1',
        recipient,
        files: ['a.pdf'],
        expiresAt: EXPIRES
      })
    ).toBe('Sent a.pdf to Grace <grace@example.test>, open until 2026-10-17 14:05 UTC.')
  })

  it('says when the send completes an invite', () => {
    expect(
      describeSend({
        status: 'sent',
        recipient,
        files: ['a.pdf'],
        expiresAt: EXPIRES,
        completedInvite: 'I1'
      })
    ).toMatch(/\nThis completes your invite\.$/)
  })

  it('passes on what to do next after an invite', () => {
    expect(describeSend({ status: 'invited', recipient, files: ['a.pdf'], next: 'Wait.' })).toBe(
      'Wait.'
    )
  })
})
