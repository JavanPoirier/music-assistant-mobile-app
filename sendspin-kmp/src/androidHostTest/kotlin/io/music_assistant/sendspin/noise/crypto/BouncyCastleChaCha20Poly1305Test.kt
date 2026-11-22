package io.music_assistant.sendspin.noise.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * The Android target encrypts with BouncyCastle, because Android 9 has no cipher under the
 * name `ChaCha20-Poly1305`. These tests hold that backend to the RFC 8439 vector and to
 * byte-for-byte agreement with the platform provider that iOS and the JVM host use.
 */
class BouncyCastleChaCha20Poly1305Test {
    private val bc = platformCrypto(CryptographyProvider.Default).aead
    private val platform = CryptographyKotlinAead(CryptographyProvider.Default)

    @Test
    fun matchesRfc8439AeadVector() = runTest {
        // RFC 8439 section 2.8.2.
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("070000004041424344454647")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = (
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip " +
                "for the future, sunscreen would be it."
            ).encodeToByteArray()
        val expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116" +
                "1ae10b594f09e26a7e902ecbd0600691",
        )

        assertContentEquals(expected, bc.encrypt(key, nonce, aad, plaintext))
        assertContentEquals(plaintext, bc.decrypt(key, nonce, aad, expected))
    }

    @Test
    fun agreesWithThePlatformCipher() = runTest {
        listOf(0, 1, 15, 16, 17, 63, 64, 65, 4096).forEach { size ->
            val key = CryptographyRandom.nextBytes(32)
            val nonce = CryptographyRandom.nextBytes(12)
            val aad = CryptographyRandom.nextBytes(size % 33)
            val plaintext = CryptographyRandom.nextBytes(size)

            val sealed = bc.encrypt(key, nonce, aad, plaintext)
            assertContentEquals(platform.encrypt(key, nonce, aad, plaintext), sealed, "size $size")
            assertContentEquals(plaintext, platform.decrypt(key, nonce, aad, sealed), "size $size")
            assertContentEquals(plaintext, bc.decrypt(key, nonce, aad, sealed), "size $size")
        }
    }

    @Test
    fun rejectsATamperedOrShortMessage() = runTest {
        val key = CryptographyRandom.nextBytes(32)
        val nonce = CryptographyRandom.nextBytes(12)
        val aad = byteArrayOf(1, 2, 3)
        val sealed = bc.encrypt(key, nonce, aad, "audio".encodeToByteArray())

        assertNull(bc.decrypt(key, nonce, aad, sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }))
        assertNull(bc.decrypt(key, nonce, aad, sealed.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }))
        assertNull(bc.decrypt(key, nonce, byteArrayOf(9), sealed))
        assertNull(bc.decrypt(key, nonce, aad, sealed.copyOf(15)))
    }

    @Test
    fun aKeyedCipherMatchesThePerMessageCipherInSequence() = runTest {
        val key = CryptographyRandom.nextBytes(32)
        val sender = bc.keyed(key)
        val receiver = bc.keyed(key)
        repeat(300) { n ->
            val nonce = ByteArray(12).also {
                it[4] = n.toByte()
            it[5] = (n shr 8).toByte()
            }
            val aad = CryptographyRandom.nextBytes(n % 5)
            val plaintext = CryptographyRandom.nextBytes(n * 13)

            val sealed = sender.encrypt(nonce, aad, plaintext)
            assertContentEquals(bc.encrypt(key, nonce, aad, plaintext), sealed, "message $n")
            assertContentEquals(plaintext, receiver.decrypt(nonce, aad, sealed), "message $n")
        }
    }

    @Test
    fun aKeyedCipherRefusesToEncryptTwiceUnderOneNonce() = runTest {
        val cipher = bc.keyed(CryptographyRandom.nextBytes(32))
        val nonce = CryptographyRandom.nextBytes(12)
        cipher.encrypt(nonce, byteArrayOf(), byteArrayOf(1))

        // BouncyCastle's reuse guard stays armed on the cached instance.
        assertFailsWith<IllegalArgumentException> { cipher.encrypt(nonce, byteArrayOf(), byteArrayOf(2)) }
    }

    @Test
    fun aKeyedCipherSurvivesAFailedDecryption() = runTest {
        val key = CryptographyRandom.nextBytes(32)
        val nonce = CryptographyRandom.nextBytes(12)
        val sealed = bc.encrypt(key, nonce, byteArrayOf(), "audio".encodeToByteArray())
        val receiver = bc.keyed(key)

        assertNull(receiver.decrypt(nonce, byteArrayOf(), sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }))
        assertContentEquals("audio".encodeToByteArray(), receiver.decrypt(nonce, byteArrayOf(), sealed))
    }

    private fun hex(value: String) =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
