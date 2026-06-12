import Foundation

// Minimal base64url helpers (no padding, url-safe alphabet) so the smoke can
// encode/decode test bytes without pulling in an extra dependency.
private func base64urlEncode(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

@main
struct Smoke {
    static func main() throws {
        // ── Existing: action + hash checks ──────────────────────────────────
        let action = try actionFromCommandJson(command: "git status", cwd: "/repo")
        if !action.contains("\"surface\":\"command\"") {
            fatalError("expected command action JSON from UniFFI")
        }

        let context = """
        {"action":\(action),"summary":"check repo status","actor":{"id":"actor-1","kind":"agent"},"risk":"low","reversible":true,"constraints":{"allowed_decisions":["approved","denied"],"challenge_required":false}}
        """
        let hash = try computeRequestHashB64(contextJson: context, expiresAt: 4102444800000)
        if hash.count != 43 {
            fatalError("expected 32-byte base64url request hash")
        }

        // ── New (PM blocker 1a): sign → verify round-trip ────────────────────
        let deviceSeedBytes = [UInt8](repeating: 7, count: 32)
        let accountSeedBytes = [UInt8](repeating: 11, count: 32)
        let deviceSeed = base64urlEncode(deviceSeedBytes)
        let accountSeed = base64urlEncode(accountSeedBytes)

        let deviceKeysJson = try deriveDeviceKeysJson(
            deviceSigningSeedB64: deviceSeed,
            deviceEncryptionSeedB64: deviceSeed
        )
        guard
            let deviceKeysData = deviceKeysJson.data(using: .utf8),
            let deviceKeys = try? JSONSerialization.jsonObject(with: deviceKeysData) as? [String: Any],
            let deviceSigningPubkey = deviceKeys["device_signing_pubkey_b64"] as? String
        else {
            fatalError("failed to parse device keys JSON")
        }

        let accountRootPubkey = try deriveSigningPubkeyB64(signingSeedB64: accountSeed)

        let deviceCert = try issueDeviceCertJson(
            accountRootSeedB64: accountSeed,
            accountId: "acct-1",
            deviceId: "dev-1",
            devicePubkeyB64: deviceSigningPubkey,
            issuedAt: 1_700_000_000_000,
            expiresAt: 4_102_444_800_000
        )

        let requestHash = try computeRequestHashB64(contextJson: context, expiresAt: 4102444800000)

        let request = """
        {"v":1,"id":"req-1","created_at":1700000000000,"expires_at":4102444800000,"approver":"acct-1","context_ciphertext":"opaque-jwe"}
        """
        let nonce = base64urlEncode([UInt8](repeating: 9, count: 16))
        // device_cert is a JWS compact string — it must be embedded as a quoted JSON string value.
        let unsignedVerdict = """
        {"v":1,"request_id":"req-1","request_hash":"\(requestHash)","decision":"approved","decided_at":1700000001000,"approver":{"account_id":"acct-1","device_id":"dev-1"},"device_cert":"\(deviceCert)"}
        """

        let verdict = try signVerdictJson(
            unsignedVerdictJson: unsignedVerdict,
            deviceSeedB64: deviceSeed,
            nonceB64: nonce
        )
        let verified = try verifyVerdictJson(
            verdictJson: verdict,
            requestJson: request,
            contextJson: context,
            accountRootPubkeyB64: accountRootPubkey,
            nowMs: 1_700_000_002_000
        )
        guard
            let verifiedData = verified.data(using: .utf8),
            let verifiedObj = try? JSONSerialization.jsonObject(with: verifiedData) as? [String: Any],
            let deviceId = verifiedObj["device_id"] as? String,
            deviceId == "dev-1"
        else {
            fatalError("sign→verify round-trip failed: device_id mismatch")
        }

        // ── New (PM blocker 1b): tampered verdict must throw ─────────────────
        // Mutate request_hash to all-zero bytes (32 bytes base64url-encoded).
        let zeroHash = base64urlEncode([UInt8](repeating: 0, count: 32))
        guard
            let verdictData = verdict.data(using: .utf8),
            var verdictObj = try? JSONSerialization.jsonObject(with: verdictData) as? [String: Any]
        else {
            fatalError("failed to parse verdict JSON for tampering")
        }
        verdictObj["request_hash"] = zeroHash
        let tamperedData = try JSONSerialization.data(withJSONObject: verdictObj)
        let tamperedVerdict = String(decoding: tamperedData, as: UTF8.self)

        var caughtExpectedError = false
        do {
            _ = try verifyVerdictJson(
                verdictJson: tamperedVerdict,
                requestJson: request,
                contextJson: context,
                accountRootPubkeyB64: accountRootPubkey,
                nowMs: 1_700_000_002_000
            )
        } catch {
            // Any thrown error from the UniFFI layer is the correct fail-closed behavior.
            caughtExpectedError = true
        }
        if !caughtExpectedError {
            fatalError("tampered verdict was accepted — Result→exception marshaling broken")
        }
    }
}
