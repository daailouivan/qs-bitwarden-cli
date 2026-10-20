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
  !!manifestSchema && manifestSchema.type === "boolean" && manifestSchema.defaultValue === false,
  JSON.stringify(manifestSchema))

check("browserIntegrationEnabled default is false in manifest.json",
  manifest.barWidget.defaults.browserIntegrationEnabled === false,
  String(manifest.barWidget.defaults.browserIntegrationEnabled))

check("browserIntegrationEnabled exists in Model.SETTINGS_SCHEMA",
  !!modelSchema && modelSchema.type === "bool" && modelSchema.defaultValue === false,
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
eq("BiometricsStatus.NotEnabledLocally", bridge.BiometricsStatus.NotEnabledLocally, 7)

done()
