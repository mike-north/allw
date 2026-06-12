import uniffi.allw_uniffi.actionFromCommandJson
import uniffi.allw_uniffi.computeRequestHashB64

fun main() {
    val action = actionFromCommandJson("git status", "/repo")
    check(action.contains("\"surface\":\"command\"")) { "expected command action JSON from UniFFI" }

    val context =
        """{"action":$action,"summary":"check repo status","actor":{"id":"actor-1","kind":"agent"},"risk":"low","reversible":true,"constraints":{"allowed_decisions":["approved","denied"],"challenge_required":false}}"""
    val hash = computeRequestHashB64(context, 4102444800000)
    check(hash.length == 43) { "expected 32-byte base64url request hash" }
}
