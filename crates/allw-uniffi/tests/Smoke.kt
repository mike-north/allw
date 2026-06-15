import uniffi.allw_uniffi.actionFromCommandJson
import uniffi.allw_uniffi.computeRequestHashB64
import uniffi.allw_uniffi.deriveDeviceKeysJson
import uniffi.allw_uniffi.deriveSigningPubkeyB64
import uniffi.allw_uniffi.issueDeviceCertJson
import uniffi.allw_uniffi.prepareApprovalJson
import uniffi.allw_uniffi.signVerdictJson
import uniffi.allw_uniffi.verifyVerdictJson
import uniffi.allw_uniffi.AllwFfiException
import java.util.Base64

// Minimal base64url helper (no padding, url-safe alphabet).
private fun base64urlEncode(bytes: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

// Smoke-grade extraction of a top-level JSON string value. CI's `kotlinc` classpath has no
// `org.json`, so we avoid an external JSON dependency (mirroring smoke.swift, which uses only
// Foundation). These UniFFI outputs are simple objects whose string values are base64url/ascii
// with no embedded quotes, so a non-greedy quoted capture is sufficient.
private fun jsonStringField(json: String, key: String): String {
    val match = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(json)
        ?: error("key $key not found in JSON")
    return match.groupValues[1]
}

fun main() {
    // ── Existing: action + hash checks ──────────────────────────────────────
    val action = actionFromCommandJson("git status", "/repo")
    check(action.contains("\"surface\":\"command\"")) { "expected command action JSON from UniFFI" }

    val context =
        """{"action":$action,"summary":"check repo status","actor":{"id":"actor-1","kind":"agent"},"risk":"low","reversible":true,"constraints":{"allowed_decisions":["approved","denied"],"challenge_required":false}}"""
    val hash = computeRequestHashB64(context, 4102444800000)
    check(hash.length == 43) { "expected 32-byte base64url request hash" }

    // ── New (PM blocker 1a): sign → verify round-trip ────────────────────────
    val deviceSeed = base64urlEncode(ByteArray(32) { 7 })
    val accountSeed = base64urlEncode(ByteArray(32) { 11 })

    val deviceKeysJson = deriveDeviceKeysJson(deviceSeed, deviceSeed)
    val deviceSigningPubkey = jsonStringField(deviceKeysJson, "device_signing_pubkey_b64")

    val accountRootPubkey = deriveSigningPubkeyB64(accountSeed)

    val deviceCert = issueDeviceCertJson(
        accountSeed, "acct-1", "dev-1", deviceSigningPubkey,
        1_700_000_000_000L, 4_102_444_800_000L
    )

    val requestHash = computeRequestHashB64(context, 4102444800000)
    val request =
        """{"v":1,"id":"req-1","created_at":1700000000000,"expires_at":4102444800000,"approver":"acct-1","context_ciphertext":"opaque-jwe"}"""
    val nonce = base64urlEncode(ByteArray(16) { 9 })
    // device_cert is a JWS compact string — it must be embedded as a quoted JSON string value.
    val unsignedVerdict =
        """{"v":1,"request_id":"req-1","request_hash":"$requestHash","decision":"approved","decided_at":1700000001000,"approver":{"account_id":"acct-1","device_id":"dev-1"},"device_cert":"$deviceCert"}"""

    val verdict = signVerdictJson(unsignedVerdict, deviceSeed, nonce)
    val verified = verifyVerdictJson(verdict, request, context, accountRootPubkey, 1_700_000_002_000L)
    check(verified.contains("\"device_id\":\"dev-1\"")) {
        "sign→verify round-trip failed: device_id mismatch"
    }

    // ── New (PM blocker 1b): tampered verdict must throw ─────────────────────
    // Mutate request_hash to all-zero bytes (32 bytes base64url-encoded).
    val zeroHash = base64urlEncode(ByteArray(32) { 0 })
    val tamperedVerdict =
        Regex("\"request_hash\"\\s*:\\s*\"[^\"]*\"").replaceFirst(verdict, "\"request_hash\":\"$zeroHash\"")
    check(tamperedVerdict != verdict) { "tamper precondition failed: request_hash not present in signed verdict" }

    var caughtExpectedError = false
    try {
        verifyVerdictJson(tamperedVerdict, request, context, accountRootPubkey, 1_700_000_002_000L)
    } catch (_: AllwFfiException) {
        // Any AllwFfiException from the UniFFI layer is the correct fail-closed behavior.
        caughtExpectedError = true
    }
    check(caughtExpectedError) { "tampered verdict was accepted — Result→exception marshaling broken" }

    // ── New (#140): prepare_approval_json fail-closed marshaling ─────────────
    // A valid JWE cannot be built in Kotlin (the FFI exposes no encryption); the happy path is
    // covered by Rust `ffi_smoke.rs`. Here we prove the `prepare` Result→exception marshaling works
    // for the two input-only rejection paths: a malformed JWE and a wrong-length device seed.
    var caughtMalformedJwe = false
    try {
        prepareApprovalJson(
            "NOT A JWE {{{", "dev-1", deviceSeed, "req-1", "acct-1",
            4_102_444_800_000L, emptyList(), accountRootPubkey
        )
    } catch (_: AllwFfiException) {
        caughtMalformedJwe = true
    }
    check(caughtMalformedJwe) { "prepare accepted a malformed JWE — fail-closed marshaling broken" }

    val shortSeed = base64urlEncode(ByteArray(16) { 0 })
    var caughtShortSeed = false
    try {
        prepareApprovalJson(
            "{}", "dev-1", shortSeed, "req-1", "acct-1",
            4_102_444_800_000L, emptyList(), accountRootPubkey
        )
    } catch (_: AllwFfiException) {
        caughtShortSeed = true
    }
    check(caughtShortSeed) { "prepare accepted a 16-byte device seed — fail-closed marshaling broken" }
}
