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

// BiometricsStatus matching official Bitwarden desktop
const BiometricsStatus = {
  Available: 0,
  UnlockNeeded: 1,
  HardwareUnavailable: 2,
  NotSupported: 3,
  NotEnabled: 4,
  DesktopDisconnected: 5,
  BiometricsReenrolled: 6,
  NotEnabledLocally: 7
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
        if (key) {
          state.userKeyB64 = key
          state.status = "unlocked"
          state.userId = targetUserId
          return key
        }
      }
    } catch (e) {}

    return ""
  }

  const server = net.createServer(client => {
    activeClients.add(client)

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
        const payload = Buffer.from(JSON.stringify(reply), "utf8")
        client.write(encodeFrame(payload))
      } catch (e) {}
    }

    function sendEncrypted(obj) {
      if (!encKey || !macKey) return
      try {
        const toEncrypt = Object.assign({ timestamp: Date.now() }, obj)
        const encStr = encryptEncString(JSON.stringify(toEncrypt), encKey, macKey)
        const outer = {
          messageId: obj.messageId,
          message: encStr
        }
        if (clientAppId) outer.appId = clientAppId
        client.write(encodeFrame(Buffer.from(JSON.stringify(outer), "utf8")))
      } catch (e) {}
    }

    const parser = createFrameParser(payload => {
      let rawMsg
      try {
        rawMsg = JSON.parse(payload.toString("utf8"))
      } catch (e) {
        return
      }

      if (rawMsg.appId) {
        clientAppId = String(rawMsg.appId)
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
      const command = cmd.command
      const messageId = cmd.messageId

      switch (command) {
        case "getBiometricsStatus":
        case "getBiometricsStatusForUser": {
          const userKey = resolveUserKey(cmd.userId)
          let code
          if (userKey || state.status === "unlocked") {
            code = BiometricsStatus.Available
          } else if (state.status === "unauthenticated") {
            code = BiometricsStatus.NotEnabledLocally
          } else {
            code = BiometricsStatus.UnlockNeeded
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
            // Vault is locked: notify parent Service.qml and deny for now
            process.stdout.write(JSON.stringify({
              type: "unlockRequested",
              userId: cmd.userId || state.userId || ""
            }) + "\n")
            respond({
              command: "unlockWithBiometricsForUser",
              response: false,
              messageId: messageId,
              timestamp: Date.now()
            })
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

    client.on("data", chunk => {
      try {
        parser(chunk)
      } catch (err) {
        client.destroy()
      }
    })

    client.on("close", () => {
      activeClients.delete(client)
    })

    client.on("error", () => {
      activeClients.delete(client)
    })
  })

  server.listen(socketPath, () => {
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
        handleControlMessage(msg)
      } catch (e) {}
    }
  })

  function handleControlMessage(msg) {
    if (msg.type === "shutdown") {
      cleanup()
      process.exit(0)
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
        resolveUserKey(state.userId)
      } else {
        state.userKeyB64 = ""
      }
    }
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
      socket.write(encodeFrame(payload))
    })
    process.stdin.on("data", chunk => {
      try {
        stdinParser(chunk)
      } catch (e) {
        process.exit(1)
      }
    })
    process.stdin.on("end", () => {
      socket.end()
    })
  })

  // Forward socket frames to stdout
  const socketParser = createFrameParser(payload => {
    process.stdout.write(encodeFrame(payload))
  })

  socket.on("data", chunk => {
    try {
      socketParser(chunk)
    } catch (e) {
      process.exit(1)
    }
  })

  socket.on("error", err => {
    process.exit(0)
  })

  socket.on("close", () => {
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
  decryptAutoUserKey,
  resolveSocketPath,
  resolveCacheDir
}
