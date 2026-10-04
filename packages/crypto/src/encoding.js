export const pemToBase64 = (pem) => {
  return pem
    .replace(/-----BEGIN .* KEY-----/, '')
    .replace(/-----END .* KEY-----/, '')
    .replace(/\s+/g, '')
}

export const str2ab = (base64) => {
  base64 = base64.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) {
    base64 += '='
  }
  const binaryString = atob(base64)
  const len = binaryString.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes.buffer
}

export const arrayBufferToBase64 = (buffer) => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

export const arrayBufferToPem = (buffer, label) => {
  const base64String = arrayBufferToBase64(buffer)
  return `-----BEGIN ${label}-----\n${base64String.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`
}
