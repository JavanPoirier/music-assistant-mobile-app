package io.music_assistant.sendspin.noise.crypto

import co.touchlab.kermit.Logger
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.random.CryptographyRandom
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519

/**
 * The Android platform JCA registers an X25519 `KeyPairGenerator` only from
 * API 33, and the `ChaCha20-Poly1305` cipher name only from API 29 (Conscrypt
 * has just `ChaCha20/Poly1305/NoPadding` on API 28). This module supports
 * API 28, so both come from BouncyCastle, on every API level: one code path,
 * which the JVM host tests run as it is.
 *
 * This is the lightweight API, not the `BouncyCastleProvider` JCA bridge: the
 * calls below are direct, so R8 keeps what they reach and strips the rest of
 * the library. The provider bridge registers its algorithms by reflective
 * class name and cannot be shrunk.
 */
internal actual fun platformCrypto(provider: CryptographyProvider): PlatformCrypto =
    PlatformCrypto(x25519 = BouncyCastleX25519Backend, aead = BouncyCastleChaCha20Poly1305)

private object BouncyCastleChaCha20Poly1305 : AeadBackend {
    private const val TAG_BITS = 128
    private val logger = Logger.withTag("Sendspin.NoiseCrypto")

    override suspend fun encrypt(
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray =
        process(forEncryption = true, key, nonce, associatedData, plaintext)

    override suspend fun decrypt(
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? =
        try {
            process(forEncryption = false, key, nonce, associatedData, ciphertext)
        } catch (e: InvalidCipherTextException) {
            // A tag mismatch, or input shorter than the tag. Noise treats both as a
            // forged message. A wrong key or nonce size still throws: that is a bug.
            logger.d(e) { "AEAD decrypt failed" }
            null
        }

    override fun keyed(key: ByteArray): AeadCipher = Keyed(key)

    /** A new cipher for each message: the instance holds the key and nonce state. */
    private fun process(
        forEncryption: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
        input: ByteArray,
    ): ByteArray = ChaCha20Poly1305().run(forEncryption, KeyParameter(key), nonce, associatedData, input)

    private fun ChaCha20Poly1305.run(
        forEncryption: Boolean,
        key: KeyParameter?,
        nonce: ByteArray,
        associatedData: ByteArray,
        input: ByteArray,
    ): ByteArray {
        init(forEncryption, AEADParameters(key, TAG_BITS, nonce, associatedData))
        val output = ByteArray(getOutputSize(input.size))
        val written = processBytes(input, 0, input.size, output, 0)
        doFinal(output, written)
        return output
    }

    /**
     * One cipher instance for the life of a key (one Noise CipherState), re-initialised for
     * each message with only the new nonce. The key schedule runs once, on the first init;
     * later inits pass a null key, which BouncyCastle reads as "keep the key".
     *
     * Nonce safety: BouncyCastle refuses (IllegalArgumentException) to init for encryption
     * with the nonce of the previous init under the same key, so a counter bug fails loudly
     * instead of reusing a keystream. The CipherState counter never repeats a nonce, and a
     * new key gets a new [Keyed]. Re-init for decryption with the same nonce is allowed, and
     * an init after a failed decryption starts clean. The instance is per CipherState, not
     * shared, so a loopback test that holds both Noise roles in one process (same key and
     * nonce on each side) never trips the guard.
     */
    private class Keyed(key: ByteArray) : AeadCipher {
        private val cipher = ChaCha20Poly1305()
        private var key: KeyParameter? = KeyParameter(key)

        override suspend fun encrypt(nonce: ByteArray, associatedData: ByteArray, plaintext: ByteArray): ByteArray =
            process(forEncryption = true, nonce, associatedData, plaintext)

        override suspend fun decrypt(nonce: ByteArray, associatedData: ByteArray, ciphertext: ByteArray): ByteArray? =
            try {
                process(forEncryption = false, nonce, associatedData, ciphertext)
            } catch (e: InvalidCipherTextException) {
                logger.d(e) { "AEAD decrypt failed" }
                null
            }

        // Keeps the key until a message completes: an earlier failure keys the next init again,
        // which costs one key schedule and nothing else.
        private fun process(forEncryption: Boolean, nonce: ByteArray, associatedData: ByteArray, input: ByteArray) =
            cipher.run(forEncryption, key, nonce, associatedData, input).also { key = null }
    }
}

private object BouncyCastleX25519Backend : X25519Backend {
    override suspend fun generateKeyPair(): X25519KeyPair {
        // CryptographyRandom is the same CSPRNG the rest of NoiseCrypto draws
        // PSKs and nonces from.
        val privateKey = CryptographyRandom.nextBytes(X25519.SCALAR_SIZE)
        X25519.clampPrivateKey(privateKey)
        return X25519KeyPair(privateKey = privateKey, publicKey = publicKey(privateKey))
    }

    override suspend fun publicKey(privateKey: ByteArray): ByteArray =
        ByteArray(X25519.POINT_SIZE).also {
            X25519.generatePublicKey(privateKey, 0, it, 0)
        }

    override suspend fun sharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray =
        ByteArray(X25519.POINT_SIZE).also {
            // False means an all-zero secret: the peer sent a small-order
            // point. RFC 7748 leaves the reaction to the protocol; Noise
            // cannot continue with it, so refuse rather than key off zeros.
            check(X25519.calculateAgreement(privateKey, 0, publicKey, 0, it, 0)) {
                "X25519 agreement produced an all-zero shared secret"
            }
        }
}
