import Foundation

/// Configuration the eventual Xcode target will load from Keychain after pairing.
public struct NativeDeviceCredentials: Codable, Equatable, Sendable {
    public let accountId: String
    public let deviceId: String
    public let deviceAuthToken: String
    public let deviceSigningSeedB64: String
    public let deviceCert: String

    public init(
        accountId: String,
        deviceId: String,
        deviceAuthToken: String,
        deviceSigningSeedB64: String,
        deviceCert: String
    ) {
        self.accountId = accountId
        self.deviceId = deviceId
        self.deviceAuthToken = deviceAuthToken
        self.deviceSigningSeedB64 = deviceSigningSeedB64
        self.deviceCert = deviceCert
    }
}

/// Native runtime entry point for the iOS shell.
///
/// This first slice intentionally exposes the seam without reimplementing any core behavior in
/// Swift. The current UniFFI crate already supports request hashing and verdict signing; the
/// remaining production work is to add the decrypt/pairing calls that let this runtime construct
/// `PreparedApproval` from a real relay envelope. Until then, app/UI code depends only on the
/// `ApproverCoreRuntime` protocol and remains testable with deterministic fakes.
public final class UniFfiApproverRuntime: ApproverCoreRuntime {
    private let credentials: NativeDeviceCredentials

    public init(credentials: NativeDeviceCredentials) {
        self.credentials = credentials
    }

    public func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        // The native app must decrypt `contextCiphertext`, verify actor origin, and compute the
        // WYSIWYS request hash through UniFFI here. This is deliberately not approximated in Swift:
        // accepting plaintext or UI-side hashes would violate the contract's thin-shell invariant.
        throw ApprovalInboxError.unverified(
            "UniFFI context decryption is not exposed yet for device \(credentials.deviceId)"
        )
    }

    public func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict {
        // The production implementation will call UniFFI `sign_verdict_json` with
        // `credentials.deviceSigningSeedB64` and a random nonce after `prepare` is backed by real
        // decrypted context. Leaving this fail-closed prevents a dev-mode app from signing a
        // verdict that did not pass core preparation first.
        throw ApprovalInboxError.signingFailed(
            "UniFFI verdict signing is gated until native prepare() uses core-decrypted context"
        )
    }
}
