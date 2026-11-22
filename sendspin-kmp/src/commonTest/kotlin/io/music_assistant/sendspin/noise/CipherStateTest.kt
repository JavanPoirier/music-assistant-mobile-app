package io.music_assistant.sendspin.noise

import io.music_assistant.sendspin.noise.crypto.CryptographyKotlinNoiseCrypto
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

/** CipherState keeps one AEAD cipher per key; these pin it to the per-message reference. */
class CipherStateTest {
    private val crypto = CryptographyKotlinNoiseCrypto()
    private val ad = byteArrayOf(7, 7)

    private fun nonce(counter: Int) = ByteArray(12).also {
        it[4] = counter.toByte()
    it[5] = (counter shr 8).toByte()
    }

    private fun keyed(key: ByteArray) = CipherState(crypto).apply { initializeKey(key) }

    @Test
    fun manyMessagesInSequenceMatchTheReferenceAndDecrypt() = runTest {
        val key = Random(1).nextBytes(KEY_LEN)
        val sender = keyed(key)
        val receiver = keyed(key)
        val random = Random(2)
        repeat(600) { n ->
            val plaintext = random.nextBytes(n % 97 * 41)
            val sealed = sender.encryptWithAd(ad, plaintext)
            assertContentEquals(crypto.aeadEncrypt(key, nonce(n), ad, plaintext), sealed, "message $n")
            assertContentEquals(plaintext, receiver.decryptWithAd(ad, sealed), "message $n")
        }
    }

    @Test
    fun aNewKeyGetsAFreshCipher() = runTest {
        val first = Random(3).nextBytes(KEY_LEN)
        val second = Random(4).nextBytes(KEY_LEN)
        val cipher = keyed(first)
        val sealed = cipher.encryptWithAd(ad, byteArrayOf(1, 2, 3))

        cipher.initializeKey(second)
        assertContentEquals(
            crypto.aeadEncrypt(second, nonce(0), ad, byteArrayOf(4)),
            cipher.encryptWithAd(ad, byteArrayOf(4)),
        )

        // Re-keying resets the counter (Noise InitializeKey). A cipher kept from the old key
        // would refuse nonce 0 again, or encrypt under the old key.
        cipher.initializeKey(first)
        assertContentEquals(sealed, cipher.encryptWithAd(ad, byteArrayOf(1, 2, 3)))
    }

    @Test
    fun aFailedDecryptionLeavesTheCipherUsable() = runTest {
        val key = Random(5).nextBytes(KEY_LEN)
        val sealed = keyed(key).encryptWithAd(ad, byteArrayOf(9, 8, 7))
        val receiver = keyed(key)

        assertFailsWith<NoiseException> {
            receiver.decryptWithAd(ad, sealed.copyOf().also { it[0] = (it[0] + 1).toByte() })
        }
        assertContentEquals(byteArrayOf(9, 8, 7), receiver.decryptWithAd(ad, sealed))
    }
}
