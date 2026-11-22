package io.music_assistant.sendspin.noise

import io.music_assistant.sendspin.api.WireVersion
import io.music_assistant.sendspin.noise.crypto.CryptographyKotlinNoiseCrypto
import io.music_assistant.sendspin.wire.BinaryFrames
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import java.lang.management.ManagementFactory
import kotlin.random.Random
import kotlin.test.Test

/**
 * Opt-in microbenchmark of the source send path for one 20 ms PCM chunk (3,840 bytes):
 * framing plus AEAD encryption, as `NoiseSession.sendBinaryFrame` runs it, without the
 * WebSocket. The `before` variants rebuild the earlier path (a timestamped body copied
 * into a typed frame, and a new key and cipher for each message) next to the current one.
 * The variants run interleaved round by round, so load on the host hits them alike. It
 * prints ns/op and bytes allocated per op and asserts nothing, because timings on a
 * shared CI host are noise. Run it with:
 *
 * `SENDSPIN_BENCH=1 ./gradlew :sendspin-kmp:testAndroidHostTest --tests '*SourceSendPathBenchmark' --rerun -i`
 */
class SourceSendPathBenchmark {
    private val crypto = CryptographyKotlinNoiseCrypto()
    private val key = Random(1).nextBytes(KEY_LEN)
    private val audio = Random(2).nextBytes(PCM_CHUNK_BYTES)
    private val transport = NoiseTransport(
        CipherState(crypto).apply { initializeKey(key) },
        CipherState(crypto),
        ByteArray(HASH_LEN),
    )
    private val plaintext = Random(3).nextBytes(1 + BinaryFrames.TIMESTAMP_BYTES + PCM_CHUNK_BYTES)
    private var serverMicros = 1_000_000L
    private var beforeNonce = 0uL
    private var sink = 0

    @Test
    fun sourceChunkSendPath() = runBlocking {
        assumeTrue("set SENDSPIN_BENCH=1 to run", System.getenv("SENDSPIN_BENCH") == "1")
        val variants = linkedMapOf<String, suspend () -> Unit>(
            "send path, before" to { sink += encryptBefore(frameBefore()).size },
            "send path, after" to { sink += transport.encrypt(frameAfter()).size },
            "framing only, before" to { sink += frameBefore().size },
            "framing only, after" to { sink += frameAfter().size },
            "encrypt only, before" to { sink += encryptBefore(plaintext).size },
            "encrypt only, after" to { sink += transport.encrypt(plaintext).size },
        )
        repeat(WARMUP_ROUNDS) { variants.values.forEach { op -> repeat(ROUND_OPS) { op() } } }
        val samples = variants.keys.associateWith { mutableListOf<Pair<Double, Double>>() }
        repeat(ROUNDS) {
            variants.forEach { (name, op) -> samples.getValue(name) += measure(op) }
        }
        samples.forEach { (name, rounds) ->
            val ns = rounds.map { it.first }.sorted()
            val bytes = rounds.map { it.second }.sorted()
            println(
                "BENCH %-22s median %6.0f ns/op (min %6.0f, max %6.0f), median %6.0f B/op".format(
                    name,
                    ns[ns.size / 2],
                    ns.first(),
                    ns.last(),
                    bytes[bytes.size / 2],
                ),
            )
        }
        println("BENCH $ROUNDS rounds x $ROUND_OPS ops per variant, sink=$sink")
    }

    /** The current path: one buffer for type, timestamp and audio. */
    private fun frameAfter(): ByteArray =
        NoiseFraming.encodeFramed(WireVersion.SPEC_1_0, BinaryFrames.sourceChunkFrame(nextMicros(), audio)).single()

    /** The earlier path: the timestamped body, then a copy behind the type byte. */
    private fun frameBefore(): ByteArray {
        val micros = nextMicros()
        val body = ByteArray(BinaryFrames.TIMESTAMP_BYTES + audio.size)
        for (i in 0 until BinaryFrames.TIMESTAMP_BYTES) {
            body[i] = (micros ushr (Byte.SIZE_BITS * (BinaryFrames.TIMESTAMP_BYTES - 1 - i))).toByte()
        }
        audio.copyInto(body, BinaryFrames.TIMESTAMP_BYTES)
        return NoiseFraming.encode(WireVersion.SPEC_1_0, BinaryFrames.TYPE_SOURCE_AUDIO_CHUNK, body).single()
    }

    /** The earlier CipherState: a new nonce array, key and cipher for each message. */
    private suspend fun encryptBefore(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_BYTES)
        for (i in 0 until COUNTER_BYTES) {
            nonce[NONCE_BYTES - COUNTER_BYTES + i] = ((beforeNonce shr (Byte.SIZE_BITS * i)) and 0xFFu).toByte()
        }
        beforeNonce++
        return crypto.aeadEncrypt(key, nonce, ByteArray(0), plaintext)
    }

    private fun nextMicros(): Long = serverMicros.also { serverMicros += CHUNK_MICROS }

    private suspend fun measure(op: suspend () -> Unit): Pair<Double, Double> {
        val threads = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        val thread = Thread.currentThread().id
        val bytesBefore = threads.getThreadAllocatedBytes(thread)
        val start = System.nanoTime()
        repeat(ROUND_OPS) { op() }
        val nanos = System.nanoTime() - start
        val bytes = threads.getThreadAllocatedBytes(thread) - bytesBefore
        return nanos.toDouble() / ROUND_OPS to bytes.toDouble() / ROUND_OPS
    }

    private companion object {
        const val PCM_CHUNK_BYTES = 3840
        const val CHUNK_MICROS = 20_000L
        const val NONCE_BYTES = 12
        const val COUNTER_BYTES = 8
        const val WARMUP_ROUNDS = 3
        const val ROUNDS = 15
        const val ROUND_OPS = 10_000
    }
}
