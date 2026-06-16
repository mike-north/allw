import Foundation

#if canImport(Security)
import Security
#endif

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// Failures from the native Secure-Enclave-gated signing path. Every case is a **deny path**: the
/// runtime turns each into a thrown `ApprovalInboxError.signingFailed`, so the inbox store restores
/// the request to `pending` and no verdict is ever emitted (fail-closed, `docs/contract.md`).
public enum SecureEnclaveSigningError: Error, Equatable, CustomStringConvertible, Sendable {
    /// The human cancelled the Face ID / Touch ID prompt, or it timed out. No signature is produced.
    case biometricCancelled(String)
    /// Biometric evaluation failed (no enrolled biometrics, lockout, hardware error). Deny path.
    case biometricFailed(String)
    /// The biometric gate passed but the signing seed could not be released from the Keychain.
    case seedUnavailable(String)
    /// The biometrically-released seed material was structurally invalid (wrong length / encoding).
    case seedMalformed(String)

    public var description: String {
        switch self {
        case .biometricCancelled(let message),
            .biometricFailed(let message),
            .seedUnavailable(let message),
            .seedMalformed(let message):
            return message
        }
    }
}

/// The biometric authorization gate that MUST succeed before the signing seed is released.
///
/// Production wires `LocalAuthenticationBiometricGate` (Face ID / Touch ID). Tests inject a fake so
/// both the success and every fail-closed rejection path (cancel, no-hardware, lockout) are covered
/// without a real device — they only validate end-to-end in CI's macOS job, where a real `LAContext`
/// exists. A gate failure throws and the verdict is never signed.
public protocol BiometricGate: Sendable {
    /// Prompt for biometric authentication, throwing `SecureEnclaveSigningError` on cancel/failure.
    /// `reason` is the human-facing string shown in the system prompt.
    func authorize(reason: String) async throws
}

/// Custody boundary for the device's Ed25519 verdict-signing seed.
///
/// The seed lives in a biometric-protected Keychain item (`KeychainSigningSeedProvider`): the OS
/// will not release the bytes until the access-control policy (`kSecAccessControlBiometryCurrentSet`)
/// is satisfied with a live Face ID / Touch ID match, so the key material never leaves the
/// Secure-Enclave-guarded Keychain without per-signature biometric auth. Tests inject an in-memory
/// provider gated by a fake `BiometricGate`.
///
/// Note on key-custody scope (#23 / #141): a *true* Secure-Enclave key is P-256-only (ECDSA), but
/// the core verdict contract signs **Ed25519** (`EdDSA`). #141 therefore holds the Ed25519 seed in
/// the biometric-gated Keychain and releases it to the core signer only after biometric auth; the
/// fuller story where the seed is generated in and never materializes outside the enclave is the
/// deferred work tracked under #23.
public protocol SigningSeedProvider: Sendable {
    /// Return the base64url-encoded Ed25519 device signing seed. MUST be called only after the
    /// biometric gate has authorized; implementations that bind biometry to the Keychain item itself
    /// will additionally fail closed here if the OS denies release.
    func releaseSigningSeedB64() async throws -> String
}

/// The narrow seam over the generated UniFFI `sign_verdict_json` binding.
///
/// Mirrors `UniFfiCoreBinding`: the package compiles standalone (its local `swiftc` validation does
/// not link the generated bindings), so the runtime never references generated symbols directly. The
/// Xcode target wires this to the generated `signVerdictJson`; tests inject a fake. All verdict
/// signing crypto stays in `allw-core` — this seam only carries the JSON-string boundary.
public protocol UniFfiSignBinding: Sendable {
    /// Sign an unsigned-verdict JSON string with the released device seed and a fresh nonce,
    /// returning the canonical core `Verdict` JSON. Throws on any core signing error (fail-closed).
    func signVerdict(
        unsignedVerdictJson: String,
        deviceSeedB64: String,
        nonceB64: String
    ) throws -> String
}

/// Source of the per-signature anti-replay nonce. Production draws cryptographically secure random
/// bytes; tests inject a deterministic source so signed-verdict assertions stay stable.
public protocol VerdictNonceSource: Sendable {
    /// 16 fresh random bytes (128-bit nonce; matches the contract's verdict-nonce convention).
    func freshNonce() -> [UInt8]
}

#if canImport(LocalAuthentication)
/// Production biometric gate backed by `LAContext` (Face ID / Touch ID).
///
/// Uses `.deviceOwnerAuthenticationWithBiometrics` so a passcode fallback can never substitute for a
/// live biometric match — the acceptance criterion is *biometric* auth per signature. Cancel/system
/// errors map to fail-closed `SecureEnclaveSigningError` cases. Validated only in CI's macOS job.
public struct LocalAuthenticationBiometricGate: BiometricGate {
    public init() {}

    public func authorize(reason: String) async throws {
        let context = LAContext()
        // Each signature requires a fresh biometric match; never reuse a prior authorization.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw SecureEnclaveSigningError.biometricFailed(
                "biometric authentication is unavailable: \(policyError?.localizedDescription ?? "no enrolled biometrics")"
            )
        }
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            guard success else {
                throw SecureEnclaveSigningError.biometricFailed("biometric authentication was not satisfied")
            }
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .systemCancel, .appCancel:
                throw SecureEnclaveSigningError.biometricCancelled(
                    "biometric authentication cancelled: \(error.localizedDescription)"
                )
            default:
                throw SecureEnclaveSigningError.biometricFailed(
                    "biometric authentication failed: \(error.localizedDescription)"
                )
            }
        }
    }
}
#endif

#if canImport(Security)
/// Keychain-backed signing-seed custody with the biometric requirement bound to the item itself.
///
/// The seed is stored under an access control of `kSecAccessControlBiometryCurrentSet` +
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, so the OS will not return the bytes without a
/// live Face ID / Touch ID match against the *current* enrolled set, and the item never syncs or
/// backs up off-device. Reading it triggers the system biometric prompt; a cancel/failure surfaces
/// as a fail-closed error and no seed is released. Validated only in CI's macOS job.
public final class KeychainSigningSeedProvider: SigningSeedProvider {
    private let service: String
    private let account: String
    private let prompt: String

    public init(
        service: String = "dev.allw.ios-approver",
        account: String = "device-signing-seed",
        prompt: String = "Authenticate to sign this approval"
    ) {
        self.service = service
        self.account = account
        self.prompt = prompt
    }

    /// Store the Ed25519 signing seed under a biometric access-control policy. Called once at
    /// enrollment; the bytes are never re-exported after this point — only released under biometry.
    public func storeSigningSeedB64(_ seedB64: String) throws {
        guard let data = seedB64.data(using: .utf8) else {
            throw SecureEnclaveSigningError.seedMalformed("signing seed was not valid UTF-8")
        }
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                &accessError
            )
        else {
            let message = (accessError?.takeRetainedValue()).map { String(describing: $0) }
                ?? "unknown access-control error"
            throw SecureEnclaveSigningError.seedUnavailable(
                "failed to create biometric access control: \(message)"
            )
        }
        deleteSigningSeed()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureEnclaveSigningError.seedUnavailable(
                "Keychain add of biometric signing seed failed with status \(status)"
            )
        }
    }

    /// Delete the stored signing seed (rotation / unpairing). Idempotent.
    public func deleteSigningSeed() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public func releaseSigningSeedB64() async throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        #if canImport(LocalAuthentication)
        // Drive the biometric prompt through an LAContext so the access-control policy on the item
        // (biometryCurrentSet) is evaluated; its localizedReason is the system prompt text.
        let context = LAContext()
        context.localizedReason = prompt
        query[kSecUseAuthenticationContext as String] = context
        #endif

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let seed = String(data: data, encoding: .utf8) else {
                throw SecureEnclaveSigningError.seedMalformed("released signing seed was not valid UTF-8")
            }
            return seed
        case errSecUserCanceled:
            throw SecureEnclaveSigningError.biometricCancelled("biometric prompt was cancelled")
        case errSecAuthFailed:
            throw SecureEnclaveSigningError.biometricFailed("biometric authentication failed")
        case errSecItemNotFound:
            throw SecureEnclaveSigningError.seedUnavailable("no signing seed is enrolled on this device")
        default:
            throw SecureEnclaveSigningError.seedUnavailable(
                "Keychain release of signing seed failed with status \(status)"
            )
        }
    }
}
#endif

/// Production nonce source backed by the system CSPRNG.
public struct SystemVerdictNonceSource: VerdictNonceSource {
    public init() {}

    public func freshNonce() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 16)
        #if canImport(Security)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status == errSecSuccess {
            return bytes
        }
        #endif
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: UInt8.min...UInt8.max)
        }
        return bytes
    }
}
