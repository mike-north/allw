import Foundation

@main
struct Smoke {
    static func main() throws {
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
    }
}
