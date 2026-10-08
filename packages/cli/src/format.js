const when = (iso) => `${iso.slice(0, 16).replace('T', ' ')} UTC`

const names = (fileNames) => fileNames.join(', ')

const size = (bytes) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`
}

const from = (row) =>
  `from ${row.senderName}: ${names(row.fileNames)}, until ${when(row.expiresAt)}`

const to = (row) =>
  `to ${row.recipientName}${row.recipientEmail ? ` <${row.recipientEmail}>` : ''}: ${names(row.fileNames)}, until ${when(row.expiresAt)}`

const SECTIONS = [
  ['inbound', 'active', 'Sent to you', (row) => `${row.linkId}  ${from(row)}`],
  ['inbound', 'awaitingAcceptance', 'Invites to accept from the invite email', from],
  ['inbound', 'awaitingUpload', 'Invites you accepted, waiting for the sender', from],
  ['outbound', 'active', 'Sent by you', (row) => `${row.linkId}  ${to(row)}`],
  ['outbound', 'awaitingAcceptance', 'Invites waiting for the recipient', to],
  ['outbound', 'awaitingUpload', 'Invites accepted; send the same files to complete them', to]
]

export const describeList = (data) => {
  const blocks = SECTIONS.filter(([direction, stage]) => data[direction]?.[stage]?.length).map(
    ([direction, stage, title, line]) =>
      [`${title}:`, ...data[direction][stage].map((row) => `  ${line(row)}`)].join('\n')
  )
  return blocks.length ? blocks.join('\n\n') : 'Nothing is open.'
}

export const describeRead = (data) =>
  [
    `Saved to ${data.directory}:`,
    ...data.files.map((file) => `  ${file.name} (${size(file.size)})`)
  ].join('\n')

export const describeSend = (data) => {
  if (data.status === 'invited') return data.next

  const lines = [
    `Sent ${names(data.files)} to ${data.recipient.name} <${data.recipient.email}>, open until ${when(data.expiresAt)}.`
  ]
  if (data.completedInvite) lines.push('This completes your invite.')
  return lines.join('\n')
}
