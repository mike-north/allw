import Foundation

#if canImport(Security)
import Security
#endif

/// Errors from the native credential persistence seam. These all fail closed: missing or stale
/// device trust material prevents verified rendering and signing rather than falling back to
/// relay-supplied trust state.
public enum NativeCredentialStoreError: Error, Equatable, CustomStringConvertible, Sendable {
    case missingPairedDevice(String)
    case invalidAccountStateSequence(accountId: String, sequence: Int64)
    case staleAccountStateSequence(accountId: String, stored: Int64, attempted: Int64)
    case unverifiedRelayAccountState(accountId: String, relayMaxSequence: Int64, verifiedSequence: Int64)
    case keychainFailure(String)

    public var description: String {
        switch self {
        case .missingPairedDevice(let message):
            return message
        case .invalidAccountStateSequence(let accountId, let sequence):
            return "invalid account-state sequence \(sequence) for account '\(accountId)'"
        case .staleAccountStateSequence(let accountId, let stored, let attempted):
            return "account '\(accountId)' rejected stale account-state sequence \(attempted); floor is \(stored)"
        case .unverifiedRelayAccountState(let accountId, let relayMaxSequence, let verifiedSequence):
            return "account '\(accountId)' relay advertised sequence \(relayMaxSequence), but only \(verifiedSequence) verified"
        case .keychainFailure(let message):
            return message
        }
    }
}

/// Storage boundary for paired device credentials and the account-state rollback floor.
///
/// Production uses `KeychainNativeCredentialStorage`; tests inject an in-memory implementation.
/// Keeping the boundary narrow prevents UI and runtime code from trusting relay-distributed
/// account state until a root-verified sequence has durably raised the local floor.
public protocol NativeCredentialStorage: AnyObject {
    func loadCredentials() async throws -> NativeDeviceCredentials?
    func saveCredentials(_ credentials: NativeDeviceCredentials) async throws
    func loadHighestAccountStateSequence(accountId: String) async throws -> Int64?
    func saveHighestAccountStateSequence(accountId: String, sequence: Int64) async throws
}

/// Coordinates native credential persistence with the enrollment spec's device-side
/// account-state sequence floor.
public final class NativeCredentialStore {
    private let storage: NativeCredentialStorage

    public init(storage: NativeCredentialStorage) {
        self.storage = storage
    }

    /// Persist the paired device material returned by the relay pairing flow. The device bearer
    /// token is stored alongside local signing material because device-scoped relay endpoints
    /// require it before the app can fetch account state, connect presence, or publish verdicts.
    public func savePairedDevice(_ credentials: NativeDeviceCredentials) async throws {
        try await storage.saveCredentials(credentials)
    }

    /// Load the paired device credentials, returning `nil` before first-run pairing completes.
    public func loadPairedDevice() async throws -> NativeDeviceCredentials? {
        try await storage.loadCredentials()
    }

    /// Accept a root-verified account-state sequence and durably raise the local floor.
    ///
    /// The relay returns opaque account-state JWS documents plus monotonic `max_sequence`
    /// metadata. The app must reject rollback in two directions: below the stored local floor,
    /// and below a relay-advertised sequence that no fetched root-signed document verifies.
    @discardableResult
    public func acceptVerifiedAccountState(
        accountId: String,
        relayMaxSequence: Int64?,
        verifiedSequence: Int64
    ) async throws -> Int64 {
        try validateNonNegative(accountId: accountId, sequence: verifiedSequence)
        if let relayMaxSequence {
            try validateNonNegative(accountId: accountId, sequence: relayMaxSequence)
            guard verifiedSequence >= relayMaxSequence else {
                throw NativeCredentialStoreError.unverifiedRelayAccountState(
                    accountId: accountId,
                    relayMaxSequence: relayMaxSequence,
                    verifiedSequence: verifiedSequence
                )
            }
        }

        let stored = try await storage.loadHighestAccountStateSequence(accountId: accountId)
        if let stored, verifiedSequence < stored {
            throw NativeCredentialStoreError.staleAccountStateSequence(
                accountId: accountId,
                stored: stored,
                attempted: verifiedSequence
            )
        }

        let next = max(stored ?? verifiedSequence, verifiedSequence)
        if stored != next {
            try await storage.saveHighestAccountStateSequence(accountId: accountId, sequence: next)
        }
        return next
    }

    private func validateNonNegative(accountId: String, sequence: Int64) throws {
        if sequence < 0 {
            throw NativeCredentialStoreError.invalidAccountStateSequence(accountId: accountId, sequence: sequence)
        }
    }
}

#if canImport(Security)
/// Keychain-backed native credential storage for the eventual iOS/macOS app target.
///
/// This stores only the app's local credential bundle and account-state sequence floor. Core
/// cryptographic validation remains in Rust/UniFFI; the Keychain is just the platform persistence
/// mechanism that keeps the relay bearer token and local signing seed out of ordinary app files.
public final class KeychainNativeCredentialStorage: NativeCredentialStorage {
    private let service: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(service: String = "dev.allw.ios-approver") {
        self.service = service
    }

    public func loadCredentials() async throws -> NativeDeviceCredentials? {
        guard let data = try loadData(account: "paired-device") else {
            return nil
        }
        return try decoder.decode(NativeDeviceCredentials.self, from: data)
    }

    public func saveCredentials(_ credentials: NativeDeviceCredentials) async throws {
        try saveData(encoder.encode(credentials), account: "paired-device")
    }

    public func loadHighestAccountStateSequence(accountId: String) async throws -> Int64? {
        guard let data = try loadData(account: accountStateFloorAccount(accountId)) else {
            return nil
        }
        guard let raw = String(data: data, encoding: .utf8), let sequence = Int64(raw) else {
            throw NativeCredentialStoreError.keychainFailure(
                "Keychain account-state floor for account '\(accountId)' is malformed"
            )
        }
        if sequence < 0 {
            throw NativeCredentialStoreError.invalidAccountStateSequence(accountId: accountId, sequence: sequence)
        }
        return sequence
    }

    public func saveHighestAccountStateSequence(accountId: String, sequence: Int64) async throws {
        try saveData(Data(String(sequence).utf8), account: accountStateFloorAccount(accountId))
    }

    private func accountStateFloorAccount(_ accountId: String) -> String {
        "account-state-floor:\(accountId)"
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func loadData(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw NativeCredentialStoreError.keychainFailure("Keychain load failed with status \(status)")
        }
        return data
    }

    private func saveData(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        let attributes = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw NativeCredentialStoreError.keychainFailure("Keychain update failed with status \(updateStatus)")
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw NativeCredentialStoreError.keychainFailure("Keychain add failed with status \(addStatus)")
        }
    }
}
#endif
