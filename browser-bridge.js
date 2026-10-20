// browser-bridge.js -- Bitwarden native messaging host & IPC server bridge
// Speaks the Bitwarden browser extension protocol to provide biometric unlock
// and status synchronization matching the official Bitwarden desktop client.

"use strict"

const fs = require("fs")
const path = require("path")
const net = require("net")
const crypto = require("crypto")

const DEFAULT_SOCKET_SUBPATH = path.join("com.bitwarden.desktop", "s.bw")
const MAX_FRAME_LEN = 1024 * 1024 // 1 MB max frame limit
const DEBUG = Boolean(process.env.QS_BITWARDEN_DEBUG)

function redactSensitive(obj) {
  if (!obj || typeof obj !== "object") return obj
  const out = Array.isArray(obj) ? [] : {}
  for (const k of Object.keys(obj)) {
    if (/userKey|session|secret|password|privateKey/i.test(k)) {
      out[k] = "[REDACTED]"
    } else if (typeof obj[k] === "object") {
      out[k] = redactSensitive(obj[k])
    } else {
      out[k] = obj[k]
    }
  }
  return out
}

function logDebug(tag, msg) {
  if (!DEBUG) return
  try {
    const text = typeof msg === "object" ? JSON.stringify(redactSensitive(msg)) : String(msg)
    process.stderr.write(`[${new Date().toISOString()}][PID ${process.pid}][${tag}] ${text}\n`)
  } catch (e) {}
}

// BiometricsStatus matching official Bitwarden desktop
const BiometricsStatus = {
  Available: 0,
  UnlockNeeded: 1,
  HardwareUnavailable: 2,
  AutoSetupNeeded: 3,
  ManualSetupNeeded: 4,
  PlatformUnsupported: 5,
  DesktopDisconnected: 6,
  NotEnabledLocally: 7,
  NotEnabledInConnectedDesktopApp: 8,
  NativeMessagingPermissionMissing: 9
}

function resolveCacheDir(home, xdgCacheHome) {
  if (xdgCacheHome && xdgCacheHome.startsWith("/")) return xdgCacheHome
  const h = home || process.env.HOME || ""
  return path.join(h, ".cache")
}

function resolveSocketPath(home, xdgCacheHome) {
  return path.join(resolveCacheDir(home, xdgCacheHome), DEFAULT_SOCKET_SUBPATH)
}

// -----------------------------------------------------------------------------
// Framing: 4-byte little-endian length prefix
// -----------------------------------------------------------------------------

function createFrameParser(onMessage) {
  let buffer = Buffer.alloc(0)
  return function handleData(chunk) {
    if (!chunk || chunk.length === 0) return
    buffer = Buffer.concat([buffer, chunk])
    while (buffer.length >= 4) {
      const length = buffer.readUInt32LE(0)
      if (length > MAX_FRAME_LEN) {
        throw new Error("Frame length " + length + " exceeds maximum allowed " + MAX_FRAME_LEN)
      }
      if (buffer.length < 4 + length) {
        break // Wait for remainder of frame
      }
      const payload = buffer.subarray(4, 4 + length)
      buffer = buffer.subarray(4 + length)
      onMessage(payload)
    }
  }
}

function encodeFrame(payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8")
  const header = Buffer.alloc(4)
  header.writeUInt32LE(buf.length, 0)
  return Buffer.concat([header, buf])
}

// -----------------------------------------------------------------------------
// Cryptography: RSA-OAEP SHA-1 & EncString (AES-256-CBC + HMAC-SHA256)
// -----------------------------------------------------------------------------

function encryptSharedSecret(publicKeyB64, secretBuffer) {
  const keyObj = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64, "base64"),
    format: "der",
    type: "spki"
  })
  const encrypted = crypto.publicEncrypt({
    key: keyObj,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha1"
  }, secretBuffer)
  return encrypted.toString("base64")
}

function decryptEncString(encStr, encKey, macKey) {
  if (typeof encStr !== "string" || !encStr.startsWith("2.")) return null
  const parts = encStr.slice(2).split("|")
  if (parts.length !== 3) return null
  const iv = Buffer.from(parts[0], "base64")
  const ciphertext = Buffer.from(parts[1], "base64")
  const mac = Buffer.from(parts[2], "base64")
  if (iv.length !== 16 || mac.length !== 32) return null

  const computedMac = crypto.createHmac("sha256", macKey)
    .update(Buffer.concat([iv, ciphertext]))
    .digest()
  if (!crypto.timingSafeEqual(computedMac, mac)) return null

  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", encKey, iv)
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return decrypted.toString("utf8")
  } catch (e) {
    return null
  }
}

function encryptEncString(plaintext, encKey, macKey) {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv)
  const plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8")
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()])
  const mac = crypto.createHmac("sha256", macKey)
    .update(Buffer.concat([iv, ciphertext]))
    .digest()
  return "2." + iv.toString("base64") + "|" + ciphertext.toString("base64") + "|" + mac.toString("base64")
}

function formatEncStringObject(encStr) {
  if (typeof encStr !== "string" || !encStr.startsWith("2.")) return null
  const parts = encStr.slice(2).split("|")
  if (parts.length !== 3) return null
  return {
    encryptedString: encStr,
    encryptionType: 2,
    data: parts[1],
    iv: parts[0],
    mac: parts[2]
  }
}

// Decrypt auto-unlock key from Bitwarden CLI's data.json using BW_SESSION
function decryptAutoUserKey(encValueB64, sessionKeyB64) {
  try {
    if (!encValueB64 || !sessionKeyB64) return null
    const encBytes = Buffer.from(encValueB64, "base64")
    if (encBytes.length < 1 + 16 + 32 + 1) return null
    const encType = encBytes[0]
    if (encType !== 2) return null // AesCbc256_HmacSha256_B64

    const iv = encBytes.subarray(1, 17)
    const mac = encBytes.subarray(17, 49)
    const data = encBytes.subarray(49)

    const sessionKey = Buffer.from(sessionKeyB64, "base64")
    if (sessionKey.length < 64) return null
    const encKey = sessionKey.subarray(0, 32)
    const macKey = sessionKey.subarray(32, 64)

    const computedMac = crypto.createHmac("sha256", macKey)
      .update(Buffer.concat([iv, data]))
      .digest()
    if (!crypto.timingSafeEqual(computedMac, mac)) return null

    const decipher = crypto.createDecipheriv("aes-256-cbc", encKey, iv)
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()])
    return decrypted.toString("base64")
  } catch (e) {
    return null
  }
}

function resolveSessionFromKeyring(slot) {
  try {
    const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim()
    const acct = slot && slot !== "default" ? "session@" + slot : "session"
    const { execSync } = require("child_process")
    const out = execSync(`secret-tool lookup service qs-bitwarden-cli account "${acct}" 2>/dev/null`, {
      encoding: "utf8",
      timeout: 2000
    }).trim()
    if (out.startsWith(bootId + " ")) {
      return out.slice(bootId.length + 1).trim()
    }
  } catch (e) {}
  return ""
}

// -----------------------------------------------------------------------------
// Noise Protocol & CBOR Codec for Bitwarden SDK IPC
// -----------------------------------------------------------------------------

const NOISE_PROTOCOL_NAME = "Noise_NN_P256_AESGCM_SHA256"
const NOISE_PADDED_NAME = Buffer.concat([
  Buffer.from(NOISE_PROTOCOL_NAME, "utf8"),
  Buffer.alloc(32 - NOISE_PROTOCOL_NAME.length, 0)
])

function noiseSha256(buf) {
  return crypto.createHash("sha256").update(buf).digest()
}

function noiseHmacSha256(key, buf) {
  return crypto.createHmac("sha256", key).update(buf).digest()
}

function noiseHkdf(ck, ikm, count) {
  const prk = noiseHmacSha256(ck, ikm)
  const outputs = []
  let prev = Buffer.alloc(0)
  for (let i = 1; i <= count; i++) {
    const input = Buffer.concat([prev, Buffer.from([i])])
    const out = noiseHmacSha256(prk, input)
    outputs.push(out)
    prev = out
  }
  return outputs
}

function noiseAesGcmSeal(key, nonceCounter, aad, plaintext) {
  const nonce = Buffer.alloc(12, 0)
  nonce.writeBigUInt64BE(BigInt(nonceCounter), 4)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce)
  if (aad && aad.length > 0) {
    cipher.setAAD(aad)
  }
  const ciphertext = cipher.update(plaintext)
  cipher.final()
  const tag = cipher.getAuthTag()
  return Buffer.concat([ciphertext, tag])
}

function noiseAesGcmOpen(key, nonceCounter, aad, sealed) {
  if (sealed.length < 16) throw new Error("Ciphertext too short")
  const nonce = Buffer.alloc(12, 0)
  nonce.writeBigUInt64BE(BigInt(nonceCounter), 4)
  const ciphertext = sealed.subarray(0, sealed.length - 16)
  const tag = sealed.subarray(sealed.length - 16)
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce)
  if (aad && aad.length > 0) {
    decipher.setAAD(aad)
  }
  decipher.setAuthTag(tag)
  const plaintext = decipher.update(ciphertext)
  const final = decipher.final()
  return Buffer.concat([plaintext, final])
}

function decodeCbor(buf) {
  let offset = 0
  function readUint(info) {
    if (info < 24) return info
    if (info === 24) {
      if (offset >= buf.length) throw new Error("Unexpected end of CBOR")
      const v = buf.readUInt8(offset)
      offset += 1
      return v
    }
    if (info === 25) {
      if (offset + 2 > buf.length) throw new Error("Unexpected end of CBOR")
      const v = buf.readUInt16BE(offset)
      offset += 2
      return v
    }
    if (info === 26) {
      if (offset + 4 > buf.length) throw new Error("Unexpected end of CBOR")
      const v = buf.readUInt32BE(offset)
      offset += 4
      return v
    }
    if (info === 27) {
      if (offset + 8 > buf.length) throw new Error("Unexpected end of CBOR")
      const v = Number(buf.readBigUInt64BE(offset))
      offset += 8
      return v
    }
    throw new Error("Invalid uint info: " + info)
  }

  function parseItem() {
    if (offset >= buf.length) throw new Error("Unexpected end of CBOR")
    const initial = buf[offset++]
    const major = initial >> 5
    const info = initial & 0x1f

    if (major === 0) {
      return readUint(info)
    } else if (major === 1) {
      return -1 - readUint(info)
    } else if (major === 2) {
      const len = readUint(info)
      if (offset + len > buf.length) throw new Error("Unexpected end of CBOR")
      const b = buf.subarray(offset, offset + len)
      offset += len
      return b
    } else if (major === 3) {
      const len = readUint(info)
      if (offset + len > buf.length) throw new Error("Unexpected end of CBOR")
      const s = buf.toString("utf8", offset, offset + len)
      offset += len
      return s
    } else if (major === 4) {
      const len = readUint(info)
      const arr = []
      for (let i = 0; i < len; i++) {
        arr.push(parseItem())
      }
      return arr
    } else if (major === 5) {
      const len = readUint(info)
      const obj = {}
      for (let i = 0; i < len; i++) {
        const k = parseItem()
        const v = parseItem()
        obj[k] = v
      }
      return obj
    } else if (major === 7) {
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      return null
    }
    throw new Error("Unsupported major type: " + major)
  }

  return parseItem()
}

function encodeCborUint(val, major = 0) {
  const prefix = major << 5
  if (val < 24) {
    return Buffer.from([prefix | val])
  } else if (val <= 0xff) {
    return Buffer.from([prefix | 24, val])
  } else if (val <= 0xffff) {
    const b = Buffer.alloc(3)
    b[0] = prefix | 25
    b.writeUInt16BE(val, 1)
    return b
  } else if (val <= 0xffffffff) {
    const b = Buffer.alloc(5)
    b[0] = prefix | 26
    b.writeUInt32BE(val, 1)
    return b
  } else {
    const b = Buffer.alloc(9)
    b[0] = prefix | 27
    b.writeBigUInt64BE(BigInt(val), 1)
    return b
  }
}

function encodeCbor(val) {
  if (val === null || val === undefined) {
    return Buffer.from([0xf6])
  }
  if (typeof val === "boolean") {
    return Buffer.from([val ? 0xf5 : 0xf4])
  }
  if (typeof val === "number") {
    if (Number.isInteger(val)) {
      if (val >= 0) return encodeCborUint(val, 0)
      return encodeCborUint(-1 - val, 1)
    }
  }
  if (typeof val === "string") {
    const strBuf = Buffer.from(val, "utf8")
    return Buffer.concat([encodeCborUint(strBuf.length, 3), strBuf])
  }
  if (Buffer.isBuffer(val)) {
    return Buffer.concat([encodeCborUint(val.length, 2), val])
  }
  if (Array.isArray(val)) {
    const bufs = [encodeCborUint(val.length, 4)]
    for (const item of val) bufs.push(encodeCbor(item))
    return Buffer.concat(bufs)
  }
  if (typeof val === "object") {
    const keys = Object.keys(val)
    const bufs = [encodeCborUint(keys.length, 5)]
    for (const k of keys) {
      bufs.push(encodeCbor(k))
      bufs.push(encodeCbor(val[k]))
    }
    return Buffer.concat(bufs)
  }
  throw new Error("Unsupported type for CBOR encoding: " + typeof val)
}

function processControlMessage(msg, state, notifyUnlockSuccess, notifyUnlockFailure, resolveUserKey, cleanup) {
  if (!msg || typeof msg !== "object") return

  if (msg.type === "shutdown") {
    if (cleanup) cleanup()
    process.exit(0)
  }

  if (msg.type === "unlockCancelled" || msg.type === "unlockFailed") {
    if (notifyUnlockFailure) notifyUnlockFailure()
    return
  }

  if (msg.type === "status") {
    state.status = String(msg.status || "locked")
    state.userId = String(msg.userId || state.userId || "")
    state.slot = String(msg.slot || state.slot || "default")
    state.appDataDir = String(msg.appDataDir || state.appDataDir || "")

    if (msg.userKeyB64) {
      state.userKeyB64 = String(msg.userKeyB64)
    }

    if (msg.session) {
      state.session = String(msg.session)
    }

    if (state.status === "unlocked") {
      const key = resolveUserKey ? resolveUserKey(state.userId) : ""
      if (key) {
        if (notifyUnlockSuccess) notifyUnlockSuccess(key)
      } else {
        // Retry resolution if data.json or keyring session write is slightly lagging status change
        let retries = 10
        const pollKey = () => {
          const k = resolveUserKey ? resolveUserKey(state.userId) : ""
          if (k) {
            if (notifyUnlockSuccess) notifyUnlockSuccess(k)
          } else if (--retries > 0) {
            setTimeout(pollKey, 50)
          }
        }
        setTimeout(pollKey, 20)
      }
    } else if (state.status === "unauthenticated") {
      state.userKeyB64 = ""
      if (notifyUnlockFailure) notifyUnlockFailure()
    } else {
      // Status is "locked" or "checking" - vault is locked/unlocking.
      // Clear cached key so stale secrets are never returned, but DO NOT
      // fail pending unlock requests that are actively awaiting the user's input!
      state.userKeyB64 = ""
    }
  }
}

// -----------------------------------------------------------------------------
// Server Mode: Listens on s.bw UNIX domain socket
// -----------------------------------------------------------------------------

function runServer(options = {}) {
  const socketPath = options.socketPath || resolveSocketPath(process.env.HOME, process.env.XDG_CACHE_HOME)
  const socketDir = path.dirname(socketPath)

  let state = {
    status: "locked", // "unlocked" | "locked" | "unauthenticated"
    userId: "",
    slot: "default",
    userKeyB64: "",
    session: "",
    appDataDir: ""
  }

  // Ensure socket directory exists
  try {
    fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 })
  } catch (e) {}

  // Remove existing socket file if present
  try {
    if (fs.existsSync(socketPath)) {
      fs.unlinkSync(socketPath)
    }
  } catch (e) {}

  const activeClients = new Set()
  const pendingUnlockCallbacks = []

  function notifyUnlockSuccess(key) {
    logDebug("NOTIFY_UNLOCK_SUCCESS", { keyLen: key ? key.length : 0, count: pendingUnlockCallbacks.length })
    while (pendingUnlockCallbacks.length > 0) {
      const cb = pendingUnlockCallbacks.shift()
      try {
        cb(key)
      } catch (e) {}
    }
  }

  function notifyUnlockFailure() {
    logDebug("NOTIFY_UNLOCK_FAILURE", { count: pendingUnlockCallbacks.length })
    while (pendingUnlockCallbacks.length > 0) {
      const cb = pendingUnlockCallbacks.shift()
      try {
        cb(null)
      } catch (e) {}
    }
  }

  function resolveUserKey(userId) {
    if (state.userKeyB64) return state.userKeyB64

    const dataDir = state.appDataDir || path.join(process.env.HOME || "", ".config", "Bitwarden CLI")
    const dataJsonPath = path.join(dataDir, "data.json")
    if (!fs.existsSync(dataJsonPath)) return ""

    try {
      const raw = fs.readFileSync(dataJsonPath, "utf8")
      const data = JSON.parse(raw)
      const targetUserId = userId || state.userId || data.global_account_activeAccountId || ""
      if (!targetUserId) return ""

      const storageKey = "__PROTECTED__" + targetUserId + "_user_auto"
      const encVal = data[storageKey]
      if (!encVal) return ""

      let sessionToken = state.session || process.env.BW_SESSION || ""
      if (!sessionToken) {
        sessionToken = resolveSessionFromKeyring(state.slot)
      }
      if (!sessionToken && state.slot && state.slot !== "default") {
        sessionToken = resolveSessionFromKeyring("default")
      }

      if (sessionToken) {
        const key = decryptAutoUserKey(encVal, sessionToken)
        logDebug("RESOLVE_USER_KEY", { targetUserId, hasEncVal: Boolean(encVal), hasSessionToken: Boolean(sessionToken), keySuccess: Boolean(key) })
        if (key) {
          state.userKeyB64 = key
          state.status = "unlocked"
          state.userId = targetUserId
          return key
        }
      } else {
        logDebug("RESOLVE_USER_KEY_FAIL", { targetUserId, hasEncVal: Boolean(encVal), sessionTokenFound: false })
      }
    } catch (e) {
      logDebug("RESOLVE_USER_KEY_ERR", e.message)
    }

    return ""
  }

  const server = net.createServer(client => {
    activeClients.add(client)
    logDebug("SERVER", "Client connected to s.bw")

    let clientAppId = ""
    let clientType = ""
    let extensionId = ""
    let sessionSecret = null // Buffer(64)
    let encKey = null // Buffer(32)
    let macKey = null // Buffer(32)

    function sendUnencrypted(obj) {
      try {
        const reply = Object.assign({}, obj)
        if (clientAppId && !reply.appId) reply.appId = clientAppId
        logDebug("SERVER_SEND_UNENC", reply)
        const payload = Buffer.from(JSON.stringify(reply), "utf8")
        client.write(encodeFrame(payload))
      } catch (e) {
        logDebug("SERVER_SEND_UNENC_ERR", e.message)
      }
    }

    function sendEncrypted(obj) {
      if (!encKey || !macKey) {
        logDebug("SERVER_SEND_ENC_NO_KEY", obj)
        return
      }
      try {
        const toEncrypt = Object.assign({ timestamp: Date.now() }, obj)
        const encStr = encryptEncString(JSON.stringify(toEncrypt), encKey, macKey)
        const encObj = formatEncStringObject(encStr)
        const outer = {
          messageId: obj.messageId,
          message: encObj
        }
        if (clientAppId) outer.appId = clientAppId
        logDebug("SERVER_SEND_ENC", { inner: toEncrypt, outer })
        client.write(encodeFrame(Buffer.from(JSON.stringify(outer), "utf8")))
      } catch (e) {
        logDebug("SERVER_SEND_ENC_ERR", e.message)
      }
    }

    const parser = createFrameParser(payload => {
      let rawMsg
      try {
        const rawStr = payload.toString("utf8")
        logDebug("SERVER_RECV_FRAME", rawStr)
        rawMsg = JSON.parse(rawStr)
      } catch (e) {
        logDebug("SERVER_PARSE_ERR", e.message)
        return
      }

      if (rawMsg.appId) {
        clientAppId = String(rawMsg.appId)
      }

      // Modern Bitwarden SDK IPC Protocol
      if (rawMsg.type === "bitwarden-ipc-message") {
        logDebug("SERVER_SDK_IPC_MSG", rawMsg)
        handleSdkIpcMessage(client, rawMsg)
        return
      }

      // Initial announcement from our proxy
      if (rawMsg.clientType && !rawMsg.command && !rawMsg.message) {
        clientType = String(rawMsg.clientType || "")
        extensionId = String(rawMsg.extensionId || "")
        process.stdout.write(JSON.stringify({
          type: "clientConnected",
          clientType: clientType,
          extensionId: extensionId
        }) + "\n")
        return
      }

      const inner = (rawMsg.message && typeof rawMsg.message === "object") ? rawMsg.message : rawMsg

      // Handshake: setupEncryption
      if (inner.command === "setupEncryption") {
        const pubKey = inner.publicKey
        if (!pubKey) return
        const msgId = inner.messageId !== undefined ? inner.messageId : -1
        try {
          sessionSecret = crypto.randomBytes(64)
          encKey = sessionSecret.subarray(0, 32)
          macKey = sessionSecret.subarray(32, 64)
          const sharedSecret = encryptSharedSecret(pubKey, sessionSecret)
          const resp = {
            command: "setupEncryption",
            messageId: msgId,
            sharedSecret: sharedSecret
          }
          if (clientAppId) resp.appId = clientAppId
          sendUnencrypted(resp)
        } catch (err) {
          const resp = {
            command: "setupEncryption",
            messageId: msgId,
            error: err.message
          }
          if (clientAppId) resp.appId = clientAppId
          sendUnencrypted(resp)
        }
        return
      }

      // Encrypted message payload
      const encMessage = typeof rawMsg.message === "string"
        ? rawMsg.message
        : (rawMsg.message && typeof rawMsg.message.encryptedString === "string" ? rawMsg.message.encryptedString : null)

      if (encMessage && encKey && macKey) {
        const decryptedJson = decryptEncString(encMessage, encKey, macKey)
        if (!decryptedJson) return
        let cmd
        try {
          cmd = JSON.parse(decryptedJson)
        } catch (e) {
          return
        }

        handleEncryptedCommand(cmd, sendEncrypted)
      }
    })

    function handleEncryptedCommand(cmd, respond) {
      logDebug("HANDLE_ENC_CMD", cmd)
      const command = cmd.command
      const messageId = cmd.messageId

      switch (command) {
        case "getBiometricsStatus":
        case "getBiometricsStatusForUser": {
          let code
          if (state.status === "unauthenticated") {
            code = BiometricsStatus.NotEnabledInConnectedDesktopApp
          } else {
            code = BiometricsStatus.Available
          }
          respond({
            command: command,
            messageId: messageId,
            response: code,
            timestamp: Date.now()
          })
          break
        }

        case "canEnableBiometricUnlock": {
          respond({
            command: "canEnableBiometricUnlock",
            messageId: messageId,
            response: true,
            timestamp: Date.now()
          })
          break
        }

        case "authenticateWithBiometrics": {
          const userKey = resolveUserKey(cmd.userId)
          const ok = Boolean(userKey || state.status === "unlocked")
          respond({
            command: "authenticateWithBiometrics",
            messageId: messageId,
            response: ok,
            timestamp: Date.now()
          })
          break
        }

        case "unlockWithBiometricsForUser": {
          const userKey = resolveUserKey(cmd.userId)
          if (userKey) {
            respond({
              command: "unlockWithBiometricsForUser",
              response: true,
              messageId: messageId,
              userKeyB64: userKey,
              timestamp: Date.now()
            })
          } else {
            // Vault is locked: prompt parent QuickShell to unlock
            process.stdout.write(JSON.stringify({
              type: "unlockRequested",
              userId: cmd.userId || state.userId || ""
            }) + "\n")

            let answered = false
            const timeoutTimer = setTimeout(() => {
              if (answered) return
              answered = true
              const idx = pendingUnlockCallbacks.indexOf(onUnlock)
              if (idx !== -1) pendingUnlockCallbacks.splice(idx, 1)
              respond({
                command: "unlockWithBiometricsForUser",
                response: false,
                messageId: messageId,
                timestamp: Date.now()
              })
            }, 30000)

            const onUnlock = (key) => {
              if (answered) return
              answered = true
              clearTimeout(timeoutTimer)
              if (key) {
                respond({
                  command: "unlockWithBiometricsForUser",
                  response: true,
                  messageId: messageId,
                  userKeyB64: key,
                  timestamp: Date.now()
                })
              } else {
                respond({
                  command: "unlockWithBiometricsForUser",
                  response: false,
                  messageId: messageId,
                  timestamp: Date.now()
                })
              }
            }

            pendingUnlockCallbacks.push(onUnlock)
          }
          break
        }

        default: {
          respond({
            command: command,
            messageId: messageId,
            response: false,
            timestamp: Date.now()
          })
          break
        }
      }
    }

    function handleSdkIpcMessage(client, rawMsg) {
      const origMsg = rawMsg.message || {}
      const origSource = origMsg.destination || "DesktopRenderer"
      const payloadBuf = Buffer.isBuffer(origMsg.payload)
        ? origMsg.payload
        : Buffer.from(origMsg.payload || [])

      let frame
      try {
        frame = decodeCbor(payloadBuf)
      } catch (err) {
        logDebug("SDK_CBOR_DECODE_ERR", err.message)
        return
      }

      function sendSdkEnvelope(cborBytes, topic) {
        const wrapper = {
          type: "forwarded-bitwarden-ipc-message",
          message: {
            destination: "DesktopMain",
            payload: Array.from(cborBytes),
            topic: topic || null
          },
          originalSource: origSource
        }
        logDebug("SERVER_SEND_SDK_REPLY", {
          origSource,
          topic: topic || null,
          payloadLen: cborBytes.length
        })
        client.write(encodeFrame(Buffer.from(JSON.stringify(wrapper), "utf8")))
      }

      if (frame.HandshakeStart) {
        logDebug("SDK_HANDSHAKE_START", frame.HandshakeStart.ciphersuite)
        const start = frame.HandshakeStart
        if (start.ciphersuite !== NOISE_PROTOCOL_NAME) {
          logDebug("SDK_UNSUPPORTED_SUITE", start.ciphersuite)
          return
        }

        const initiatorFrame = Buffer.isBuffer(start.noise_frame)
          ? start.noise_frame
          : Buffer.from(start.noise_frame || [])

        if (initiatorFrame.length < 65 || initiatorFrame[0] !== 0x04) {
          logDebug("SDK_INVALID_INITIATOR_KEY", initiatorFrame.length)
          return
        }

        const initiatorPub = initiatorFrame.subarray(0, 65)
        const resEcdh = crypto.createECDH("prime256v1")
        resEcdh.generateKeys()
        const resPub = resEcdh.getPublicKey()

        let ck = Buffer.from(NOISE_PADDED_NAME)
        let h = noiseSha256(NOISE_PADDED_NAME)
        h = noiseSha256(Buffer.concat([h, initiatorPub]))
        h = noiseSha256(Buffer.concat([h, initiatorFrame.subarray(65)])) // empty payload

        h = noiseSha256(Buffer.concat([h, resPub]))
        const dh = resEcdh.computeSecret(initiatorPub)
        const keys = noiseHkdf(ck, dh, 2)
        ck = keys[0]
        const tempKey = keys[1]

        const sealed = noiseAesGcmSeal(tempKey, 0, h, Buffer.alloc(0))
        h = noiseSha256(Buffer.concat([h, sealed]))

        const split = noiseHkdf(ck, Buffer.alloc(0), 2)
        client._sdkSession = {
          receiveKey: split[0], // i2r
          sendKey: split[1],    // r2i
          sendNonce: 0,
          receiveNonce: 0
        }

        const finishBytes = Buffer.concat([resPub, sealed])
        const finishCbor = encodeCbor({
          HandshakeFinish: Array.from(finishBytes)
        })

        sendSdkEnvelope(finishCbor, null)
        logDebug("SDK_HANDSHAKE_FINISH_SENT", finishBytes.length)
        return
      }

      if (frame.TransportFrame) {
        if (!client._sdkSession) {
          logDebug("SDK_NO_SESSION_SENDING_INVALIDATED", "")
          const cborInvalid = encodeCbor("CryptoInvalidated")
          sendSdkEnvelope(cborInvalid, null)
          return
        }

        const tf = frame.TransportFrame
        const tfPayload = Buffer.isBuffer(tf.payload) ? tf.payload : Buffer.from(tf.payload || [])
        let plaintext
        try {
          plaintext = noiseAesGcmOpen(client._sdkSession.receiveKey, tf.nonce, Buffer.alloc(0), tfPayload)
        } catch (err) {
          logDebug("SDK_DECRYPT_ERR", err.message)
          client._sdkSession = null
          const cborInvalid = encodeCbor("CryptoInvalidated")
          sendSdkEnvelope(cborInvalid, null)
          return
        }

        let req
        try {
          req = JSON.parse(plaintext.toString("utf8"))
        } catch (err) {
          logDebug("SDK_JSON_PARSE_ERR", err.message)
          return
        }

        logDebug("SDK_RPC_REQ", { type: req.request_type, id: req.request_id })

        function sendRpcResponse(rpcResult) {
          const respObj = {
            result: rpcResult,
            request_id: req.request_id,
            request_type: req.request_type
          }
          const respJson = Buffer.from(JSON.stringify(respObj), "utf8")
          client._sdkSession.sendNonce += 1
          const sealedResp = noiseAesGcmSeal(
            client._sdkSession.sendKey,
            client._sdkSession.sendNonce,
            Buffer.alloc(0),
            respJson
          )

          const respCbor = encodeCbor({
            TransportFrame: {
              payload: sealedResp,
              nonce: client._sdkSession.sendNonce
            }
          })

          sendSdkEnvelope(respCbor, req.response_topic || "RpcResponseMessage")
          logDebug("SDK_RPC_RESP_SENT", { type: req.request_type, id: req.request_id })
        }

        if (req.request_type === "DiscoverRequest") {
          sendRpcResponse({ Ok: { version: "2026.9.0" } })
          return
        } else if (req.request_type === "GetBiometricsStatus") {
          sendRpcResponse({ Ok: state.status === "unauthenticated" ? "NotEnabled" : "Available" })
          return
        } else if (req.request_type === "UnlockBiometrics") {
          const reqUserId = req.request && (req.request.user_id || req.request.userId)
          const key = resolveUserKey(reqUserId || state.userId)
          if (key) {
            logDebug("SDK_UNLOCK_SUCCESS", { userId: reqUserId || state.userId })
            sendRpcResponse({ Ok: { user_key: key } })
            return
          } else {
            process.stdout.write(JSON.stringify({
              type: "unlockRequested",
              userId: reqUserId || state.userId || ""
            }) + "\n")

            let answered = false
            const timeoutTimer = setTimeout(() => {
              if (answered) return
              answered = true
              const idx = pendingUnlockCallbacks.indexOf(onUnlock)
              if (idx !== -1) pendingUnlockCallbacks.splice(idx, 1)
              sendRpcResponse({ Ok: { user_key: null } })
            }, 30000)

            const onUnlock = (unlockedKey) => {
              if (answered) return
              answered = true
              clearTimeout(timeoutTimer)
              sendRpcResponse({ Ok: { user_key: unlockedKey } })
            }

            pendingUnlockCallbacks.push(onUnlock)
            return
          }
        } else if (req.request_type === "AuthenticateBiometrics") {
          sendRpcResponse({ Ok: true })
          return
        } else {
          logDebug("SDK_UNKNOWN_RPC", req.request_type)
          sendRpcResponse({ Err: "NoHandlerFound" })
          return
        }
      }

      if (frame === "CryptoInvalidated" || (frame && frame.CryptoInvalidated)) {
        logDebug("SDK_PEER_CRYPTO_INVALIDATED", "")
        client._sdkSession = null
        return
      }
    }

    client.on("data", chunk => {
      try {
        parser(chunk)
      } catch (err) {
        logDebug("CLIENT_DATA_ERR", err.message)
        client.destroy()
      }
    })

    client.on("close", () => {
      logDebug("SERVER", "Client disconnected from s.bw")
      activeClients.delete(client)
    })

    client.on("error", (err) => {
      logDebug("SERVER_CLIENT_ERR", err.message)
      activeClients.delete(client)
    })
  })

  server.listen(socketPath, () => {
    logDebug("SERVER", `Listening on ${socketPath}`)
    // Notify Service.qml that the server is ready
    process.stdout.write(JSON.stringify({
      type: "ready",
      socketPath: socketPath
    }) + "\n")
  })

  // Read control commands from Service.qml on stdin
  let stdinBuffer = ""
  process.stdin.setEncoding("utf8")
  process.stdin.on("data", chunk => {
    stdinBuffer += chunk
    const lines = stdinBuffer.split("\n")
    stdinBuffer = lines.pop()
    for (const line of lines) {
      if (!line.trim()) continue
      try {
        const msg = JSON.parse(line)
        logDebug("SERVER_CTRL_MSG", msg)
        handleControlMessage(msg)
      } catch (e) {}
    }
  })

  function handleControlMessage(msg) {
    processControlMessage(msg, state, notifyUnlockSuccess, notifyUnlockFailure, resolveUserKey, cleanup)
  }

  function cleanup() {
    try {
      for (const client of activeClients) {
        client.destroy()
      }
      server.close()
      if (fs.existsSync(socketPath)) {
        fs.unlinkSync(socketPath)
      }
    } catch (e) {}
  }

  process.on("SIGTERM", () => {
    cleanup()
    process.exit(0)
  })

  process.on("SIGINT", () => {
    cleanup()
    process.exit(0)
  })

  process.on("exit", () => {
    cleanup()
  })
}

// -----------------------------------------------------------------------------
// Proxy Mode: Browser stdio <-> s.bw UNIX domain socket
// -----------------------------------------------------------------------------

function runProxy(args) {
  logDebug("PROXY_START", args)
  const socketPath = resolveSocketPath(process.env.HOME, process.env.XDG_CACHE_HOME)

  let clientType = "chrome"
  let extensionId = ""

  // Parse browser arguments
  for (const arg of args) {
    if (arg.startsWith("chrome-extension://")) {
      clientType = "chrome"
      extensionId = arg.replace(/^chrome-extension:\/\//, "").replace(/\/.*$/, "")
      break
    } else if (arg.startsWith("{") && arg.endsWith("}")) {
      clientType = "firefox"
      extensionId = arg
      break
    } else if (arg.endsWith(".json")) {
      clientType = "firefox"
    }
  }

  if (!extensionId) {
    extensionId = clientType === "firefox"
      ? "{446900e4-71c2-419f-a6a7-df9c091e268b}"
      : "nngceckbapebfimnlniiiahkandclblb"
  }

  const socket = net.createConnection(socketPath, () => {
    logDebug("PROXY_SOCKET_CONNECTED", socketPath)
    // Send connected message to browser extension stdout
    process.stdout.write(encodeFrame(Buffer.from(JSON.stringify({ command: "connected" }), "utf8")))

    // Send announcement frame to s.bw
    const announcement = Buffer.from(JSON.stringify({
      clientType: clientType,
      extensionId: extensionId
    }), "utf8")
    socket.write(encodeFrame(announcement))

    // Forward stdin frames to socket
    const stdinParser = createFrameParser(payload => {
      logDebug("PROXY_STDIN_FRAME", payload.toString("utf8"))
      socket.write(encodeFrame(payload))
    })
    process.stdin.on("data", chunk => {
      try {
        stdinParser(chunk)
      } catch (e) {
        logDebug("PROXY_STDIN_ERR", e.message)
        process.exit(1)
      }
    })
    process.stdin.on("end", () => {
      logDebug("PROXY_STDIN_END", "")
      socket.end()
    })
  })

  // Forward socket frames to stdout
  const socketParser = createFrameParser(payload => {
    logDebug("PROXY_STDOUT_FRAME", payload.toString("utf8"))
    process.stdout.write(encodeFrame(payload))
  })

  socket.on("data", chunk => {
    try {
      socketParser(chunk)
    } catch (e) {
      logDebug("PROXY_DATA_ERR", e.message)
      process.exit(1)
    }
  })

  socket.on("error", err => {
    logDebug("PROXY_SOCKET_ERR", err.message)
    process.exit(0)
  })

  socket.on("close", () => {
    logDebug("PROXY_SOCKET_CLOSE", "")
    process.exit(0)
  })

  process.stdin.on("error", () => {
    process.exit(0)
  })
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2)
  if (args.includes("--server")) {
    runServer()
  } else {
    runProxy(args.filter(a => a !== "--proxy"))
  }
}

if (require.main === module) {
  main()
}

module.exports = {
  BiometricsStatus,
  createFrameParser,
  encodeFrame,
  encryptSharedSecret,
  decryptEncString,
  encryptEncString,
  formatEncStringObject,
  decryptAutoUserKey,
  resolveSocketPath,
  resolveCacheDir,
  decodeCbor,
  encodeCbor,
  noiseHkdf,
  noiseAesGcmSeal,
  noiseAesGcmOpen,
  NOISE_PROTOCOL_NAME,
  processControlMessage,
  redactSensitive
}
