#!/usr/bin/env node
// Tests for the browser integration feature:
// - Manifest generation and schema definitions
// - Framing (4-byte LE length header)
// - Cryptography (RSA-OAEP SHA-1, EncString AES-256-CBC + HMAC-SHA256)
// - Biometric protocol commands and responses

"use strict"

const crypto = require("crypto")
const { createSuite, loadModule, read } = require("./harness")
const bridge = require("../browser-bridge")

const Model = loadModule("BitwardenModel.js")
const { check, eq, done } = createSuite("browser-integration")

// --- Manifest and Schema definitions -----------------------------------------

const manifest = JSON.parse(read("manifest.json"))
const manifestSchema = manifest.barWidget.schema.find(s => s.key === "browserIntegrationEnabled")
const modelSchema = Model.SETTINGS_SCHEMA.find(s => s.key === "browserIntegrationEnabled")

check("browserIntegrationEnabled exists in manifest.json schema",
  !!manifestSchema && manifestSchema.type === "boolean" && manifestSchema.defaultValue === true,
  JSON.stringify(manifestSchema))

check("browserIntegrationEnabled default is true in manifest.json",
  manifest.barWidget.defaults.browserIntegrationEnabled === true,
  String(manifest.barWidget.defaults.browserIntegrationEnabled))

check("browserIntegrationEnabled exists in Model.SETTINGS_SCHEMA",
  !!modelSchema && modelSchema.type === "bool" && modelSchema.defaultValue === true,
  JSON.stringify(modelSchema))

check("browser group exists in SETTINGS_GROUPS",
  Model.SETTINGS_GROUPS.some(g => g.id === "browser" && g.label === "Browser Integration"),
  JSON.stringify(Model.SETTINGS_GROUPS))

const visible = Model.visibleSettings({ items: [] }, true)
check("browserIntegrationEnabled is included in visibleSettings",
  visible.some(e => e.key === "browserIntegrationEnabled"),
  "expected browserIntegrationEnabled in visibleSettings")

// --- Browser Manifest paths and content --------------------------------------

const dirs = Model.browserManifestDirs("/home/testuser", "/home/testuser/.config")
check("browserManifestDirs includes chromium directories",
  dirs.chromium.length >= 13,
  `got ${dirs.chromium.length} chromium directories`)

check("browserManifestDirs includes firefox directories",
  dirs.firefox.length >= 5,
  `got ${dirs.firefox.length} firefox directories`)

check("browserManifestDirs includes flatpak directories",
  dirs.chromium.some(d => d.includes(".var/app/com.google.Chrome"))
    && dirs.firefox.some(d => d.includes(".var/app/org.mozilla.firefox")),
  JSON.stringify(dirs))

const proxyPath = Model.browserProxyPath("/opt/qs-bitwarden-cli")
eq("browserProxyPath formats correctly", proxyPath, "/opt/qs-bitwarden-cli/bin/desktop_proxy")

const chromiumManifestRaw = Model.browserChromiumManifestContent(proxyPath)
const chromiumManifest = JSON.parse(chromiumManifestRaw)
eq("chromium manifest name", chromiumManifest.name, "com.8bit.bitwarden")
eq("chromium manifest type", chromiumManifest.type, "stdio")
eq("chromium manifest path", chromiumManifest.path, proxyPath)
check("chromium manifest includes official extension IDs",
  chromiumManifest.allowed_origins.includes("chrome-extension://nngceckbapebfimnlniiiahkandclblb/")
    && chromiumManifest.allowed_origins.includes("chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh/")
    && chromiumManifest.allowed_origins.includes("chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn/"),
  JSON.stringify(chromiumManifest.allowed_origins))

const firefoxManifestRaw = Model.browserFirefoxManifestContent(proxyPath)
const firefoxManifest = JSON.parse(firefoxManifestRaw)
eq("firefox manifest name", firefoxManifest.name, "com.8bit.bitwarden")
eq("firefox manifest type", firefoxManifest.type, "stdio")
eq("firefox manifest path", firefoxManifest.path, proxyPath)
check("firefox manifest includes official extension UUID",
  firefoxManifest.allowed_extensions.includes("{446900e4-71c2-419f-a6a7-df9c091e268b}"),
  JSON.stringify(firefoxManifest.allowed_extensions))

const installCmd = Model.browserManifestInstallCommand("/opt/plugin", "/home/user", "/home/user/.config", "/home/user/.cache")
check("browserManifestInstallCommand produces bash command",
  Array.isArray(installCmd) && installCmd[0] === "bash" && installCmd[2].includes("com.8bit.bitwarden.json"),
  JSON.stringify(installCmd))

const removeCmd = Model.browserManifestRemoveCommand("/home/user", "/home/user/.config", "/home/user/.cache")
check("browserManifestRemoveCommand produces bash command",
  Array.isArray(removeCmd) && removeCmd[0] === "bash" && removeCmd[2].includes("rm -f"),
  JSON.stringify(removeCmd))

// --- Protocol framing: 4-byte LE length header -------------------------------

{
  const received = []
  const parser = bridge.createFrameParser(payload => {
    received.push(payload.toString("utf8"))
  })

  const msg1 = "{\"command\":\"connected\"}"
  const frame1 = bridge.encodeFrame(msg1)
  eq("encodeFrame writes length prefix", frame1.readUInt32LE(0), Buffer.byteLength(msg1))

  // Test single complete frame
  parser(frame1)
  eq("parser reads complete frame", received.length, 1)
  eq("parsed payload matches", received[0], msg1)

  // Test fragmented frame
  const msg2 = "{\"command\":\"getBiometricsStatus\",\"messageId\":42}"
  const frame2 = bridge.encodeFrame(msg2)
  parser(frame2.subarray(0, 10))
  eq("parser holds incomplete frame", received.length, 1)
  parser(frame2.subarray(10))
  eq("parser completes fragmented frame", received.length, 2)
  eq("parsed fragmented payload matches", received[1], msg2)

  // Test two concatenated frames in one chunk
  const msg3 = "{\"msg\":3}"
  const msg4 = "{\"msg\":4}"
  const frameCombined = Buffer.concat([bridge.encodeFrame(msg3), bridge.encodeFrame(msg4)])
  parser(frameCombined)
  eq("parser processes concatenated frames", received.length, 4)
  eq("concatenated msg3 matches", received[2], msg3)
  eq("concatenated msg4 matches", received[3], msg4)
}

// --- Cryptography: EncString (AES-256-CBC + HMAC-SHA256) --------------------

{
  const encKey = crypto.randomBytes(32)
  const macKey = crypto.randomBytes(32)
  const plaintext = JSON.stringify({ hello: "bitwarden", secret: 12345 })

  const encString = bridge.encryptEncString(plaintext, encKey, macKey)
  check("encrypted string format starts with 2.", encString.startsWith("2."), encString)
  eq("encrypted string has 3 pipe-separated parts", encString.slice(2).split("|").length, 3)

  const decrypted = bridge.decryptEncString(encString, encKey, macKey)
  eq("decrypted plaintext matches original", decrypted, plaintext)

  // Tamper detection
  const parts = encString.slice(2).split("|")
  const tamperedMac = Buffer.from(parts[2], "base64")
  tamperedMac[0] ^= 0xff
  const tamperedEncString = "2." + parts[0] + "|" + parts[1] + "|" + tamperedMac.toString("base64")
  const tamperedResult = bridge.decryptEncString(tamperedEncString, encKey, macKey)
  eq("tampered MAC is rejected", tamperedResult, null)

  // Wrong key
  const wrongKey = crypto.randomBytes(32)
  eq("wrong encryption key returns null", bridge.decryptEncString(encString, wrongKey, macKey), null)
}

// --- Cryptography: RSA-OAEP SHA-1 public key encryption ----------------------

{
  // Generate a test RSA-2048 keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  })

  const publicKeyB64 = publicKey.toString("base64")
  const sessionSecret = crypto.randomBytes(64)

  const sharedSecretB64 = bridge.encryptSharedSecret(publicKeyB64, sessionSecret)
  check("sharedSecret is base64 string", typeof sharedSecretB64 === "string" && sharedSecretB64.length > 0)

  // Decrypt using private key with RSA-OAEP SHA-1
  const decryptedSecret = crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha1"
  }, Buffer.from(sharedSecretB64, "base64"))

  eq("decrypted session secret matches original 64 bytes",
    decryptedSecret.toString("hex"),
    sessionSecret.toString("hex"))
}

// --- BiometricsStatus enum values --------------------------------------------

eq("BiometricsStatus.Available", bridge.BiometricsStatus.Available, 0)
eq("BiometricsStatus.UnlockNeeded", bridge.BiometricsStatus.UnlockNeeded, 1)
eq("BiometricsStatus.HardwareUnavailable", bridge.BiometricsStatus.HardwareUnavailable, 2)
eq("BiometricsStatus.AutoSetupNeeded", bridge.BiometricsStatus.AutoSetupNeeded, 3)
eq("BiometricsStatus.ManualSetupNeeded", bridge.BiometricsStatus.ManualSetupNeeded, 4)
eq("BiometricsStatus.PlatformUnsupported", bridge.BiometricsStatus.PlatformUnsupported, 5)
eq("BiometricsStatus.DesktopDisconnected", bridge.BiometricsStatus.DesktopDisconnected, 6)
eq("BiometricsStatus.NotEnabledLocally", bridge.BiometricsStatus.NotEnabledLocally, 7)
eq("BiometricsStatus.NotEnabledInConnectedDesktopApp", bridge.BiometricsStatus.NotEnabledInConnectedDesktopApp, 8)
eq("BiometricsStatus.NativeMessagingPermissionMissing", bridge.BiometricsStatus.NativeMessagingPermissionMissing, 9)

// --- EncString object formatting for browser extension -----------------------

{
  const encKey = crypto.randomBytes(32)
  const macKey = crypto.randomBytes(32)
  const encStr = bridge.encryptEncString("test payload", encKey, macKey)
  const encObj = bridge.formatEncStringObject(encStr)

  eq("encObj.encryptedString matches encStr", encObj.encryptedString, encStr)
  eq("encObj.encryptionType is 2 (AesCbc256_HmacSha256_B64)", encObj.encryptionType, 2)
  check("encObj.iv exists and is base64", typeof encObj.iv === "string" && encObj.iv.length > 0)
  check("encObj.data exists and is base64", typeof encObj.data === "string" && encObj.data.length > 0)
  check("encObj.mac exists and is base64", typeof encObj.mac === "string" && encObj.mac.length > 0)
  eq("invalid encStr returns null", bridge.formatEncStringObject("not-valid"), null)
}

// --- Bitwarden SDK IPC: CBOR & Noise Protocol --------------------------------

{
  // Test CBOR round-trip
  const testObj = {
    str: "hello world",
    num: 12345,
    neg: -42,
    flag: true,
    n: null,
    arr: [1, 2, 3],
    bytes: Buffer.from("deadbeef", "hex")
  }
  const encoded = bridge.encodeCbor(testObj)
  const decoded = bridge.decodeCbor(encoded)
  eq("CBOR round-trip string", decoded.str, testObj.str)
  eq("CBOR round-trip num", decoded.num, testObj.num)
  eq("CBOR round-trip neg", decoded.neg, testObj.neg)
  eq("CBOR round-trip flag", decoded.flag, testObj.flag)
  eq("CBOR round-trip null", decoded.n, null)
  eq("CBOR round-trip arr length", decoded.arr.length, 3)
  eq("CBOR round-trip bytes", decoded.bytes.toString("hex"), testObj.bytes.toString("hex"))

  // Test against official SDK snow_vectors.json test vector
  function seq(from, to) {
    const arr = []
    for (let i = from; i <= to; i++) arr.push(i)
    return Buffer.from(arr)
  }

  const m1 = Buffer.from("04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354", "hex")
  const expectedM2 = "041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b913a30bb601e0c94ca717388ab2c0968"
  const expectedI2R = "44a64623c53e295e7786048e0b7d5f6811cf2b3ee55060a2a46d28d16ad11cd8"

  const resPriv = seq(33, 64)
  const ecdh = crypto.createECDH("prime256v1")
  ecdh.setPrivateKey(resPriv)
  const resPub = ecdh.getPublicKey()

  const paddedName = Buffer.concat([Buffer.from(bridge.NOISE_PROTOCOL_NAME, "utf8"), Buffer.alloc(32 - bridge.NOISE_PROTOCOL_NAME.length, 0)])
  let ck = Buffer.from(paddedName)
  let h = crypto.createHash("sha256").update(paddedName).digest()

  h = crypto.createHash("sha256").update(Buffer.concat([h, m1.subarray(0, 65)])).digest()
  h = crypto.createHash("sha256").update(Buffer.concat([h, m1.subarray(65)])).digest()
  h = crypto.createHash("sha256").update(Buffer.concat([h, resPub])).digest()

  const dh = ecdh.computeSecret(m1.subarray(0, 65))
  const keys = bridge.noiseHkdf(ck, dh, 2)
  ck = keys[0]
  const tempKey = keys[1]

  const sealed = bridge.noiseAesGcmSeal(tempKey, 0, h, Buffer.alloc(0))
  h = crypto.createHash("sha256").update(Buffer.concat([h, sealed])).digest()

  const split = bridge.noiseHkdf(ck, Buffer.alloc(0), 2)
  const i2r = split[0]
  const r2i = split[1]

  const m2 = Buffer.concat([resPub, sealed])
  eq("m2 matches official SDK test vector", m2.toString("hex"), expectedM2)
  eq("i2r matches official SDK test vector", i2r.toString("hex"), expectedI2R)

  // Transport encryption & decryption test
  const testPlaintext = Buffer.from('{"hello":"bitwarden"}', "utf8")
  const encTransport = bridge.noiseAesGcmSeal(r2i, 1, Buffer.alloc(0), testPlaintext)
  const decTransport = bridge.noiseAesGcmOpen(r2i, 1, Buffer.alloc(0), encTransport)
  eq("transport seal and open", decTransport.toString("utf8"), testPlaintext.toString("utf8"))
}

done()

