/**
 * Public-key fixtures for relay tests.
 *
 * `POST /pairing/complete` rejects small-order X25519 device keys (#248), so a device key fixture
 * must be a real, full-order X25519 public key, not a byte pattern like 32 × 0x00 (which is
 * small-order).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-6.1
 */

/**
 * A full-order X25519 public key for enrolling test devices: Alice's public key from RFC 7748
 * §6.1 (`8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`), base64url-unpadded.
 * It is a published test vector, never real key material.
 */
export const DEVICE_X25519_PUBKEY = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
