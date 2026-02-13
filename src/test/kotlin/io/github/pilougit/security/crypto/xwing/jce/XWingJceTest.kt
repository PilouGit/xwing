package io.github.pilougit.security.crypto.xwing.jce

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.apache.commons.codec.binary.Hex
import java.security.KeyPairGenerator
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KEM
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class XWingJceTest {

    data class TestVector(
        val seed: String,
        val sk: String,
        val pk: String,
        val eseed: String,
        val ct: String,
        val ss: String
    )

    init {
        Security.addProvider(XWingProvider())
    }

    private val testVectors: List<TestVector> by lazy {
        val json = this::class.java.getResource("/test-vectors.json")!!.readText()
        Gson().fromJson(json, object : TypeToken<List<TestVector>>() {}.type)
    }

    @Test
    fun `KeyPairGenerator produces valid key sizes`() {
        val kpg = KeyPairGenerator.getInstance("X-Wing")
        val kp = kpg.generateKeyPair()

        assertEquals("X-Wing", kp.public.algorithm)
        assertEquals("X-Wing", kp.private.algorithm)
        assertEquals("RAW", kp.public.format)
        assertEquals("RAW", kp.private.format)
        assertEquals(1216, kp.public.encoded.size)
        assertEquals(32, kp.private.encoded.size)
    }

    @Test
    fun `KEM encapsulate and decapsulate round-trip`() {
        val kpg = KeyPairGenerator.getInstance("X-Wing")
        val kp = kpg.generateKeyPair()

        val kem = KEM.getInstance("X-Wing")
        val encapsulator = kem.newEncapsulator(kp.public)
        val encapsulated = encapsulator.encapsulate()

        assertNotNull(encapsulated)
        assertEquals(1120, encapsulated.encapsulation().size)
        assertEquals(32, encapsulated.key().encoded.size)

        val decapsulator = kem.newDecapsulator(kp.private)
        val ss = decapsulator.decapsulate(encapsulated.encapsulation())

        assertContentEquals(encapsulated.key().encoded, ss.encoded,
            "Round-trip: shared secret mismatch")
    }

    @Test
    fun `KEM decapsulate matches test vectors`() {
        for ((i, tv) in testVectors.withIndex()) {
            val sk = XWingPrivateKey(Hex.decodeHex(tv.sk))
            val ct = Hex.decodeHex(tv.ct)
            val expectedSs = Hex.decodeHex(tv.ss)

            val kem = KEM.getInstance("X-Wing")
            val decapsulator = kem.newDecapsulator(sk)
            val ss = decapsulator.decapsulate(ct)

            assertContentEquals(expectedSs, ss.encoded,
                "Test vector ${i + 1}: ss mismatch")
        }
    }

    @Test
    fun `KEM encapsulator and decapsulator report correct sizes`() {
        val kpg = KeyPairGenerator.getInstance("X-Wing")
        val kp = kpg.generateKeyPair()

        val kem = KEM.getInstance("X-Wing")
        val encapsulator = kem.newEncapsulator(kp.public)
        assertEquals(32, encapsulator.secretSize())
        assertEquals(1120, encapsulator.encapsulationSize())

        val decapsulator = kem.newDecapsulator(kp.private)
        assertEquals(32, decapsulator.secretSize())
        assertEquals(1120, decapsulator.encapsulationSize())
    }

    @Test
    fun `TLS-like handshake - encapsulate AES-256 key and encrypt a message`() {
        val kpg = KeyPairGenerator.getInstance("X-Wing")
        val kem = KEM.getInstance("X-Wing")

        // --- Two parties: client and server each generate an X-Wing key pair ---
        val clientKp = kpg.generateKeyPair()
        val serverKp = kpg.generateKeyPair()

        // === Direction 1: Client → Server ===
        // Server encapsulates an AES-256 key using the client's public key
        val encToClient = kem.newEncapsulator(clientKp.public)
            .encapsulate(0, 32, "AES")
        val serverAesKey = encToClient.key()
        assertEquals("AES", serverAesKey.algorithm)
        assertEquals(32, serverAesKey.encoded.size) // AES-256

        // Server encrypts a message with the derived AES-256-GCM key
        val plaintext = "Hello from server, post-quantum secure!".toByteArray()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, serverAesKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        // Client decapsulates to recover the same AES-256 key
        val clientAesKey = kem.newDecapsulator(clientKp.private)
            .decapsulate(encToClient.encapsulation(), 0, 32, "AES")
        assertEquals("AES", clientAesKey.algorithm)
        assertContentEquals(serverAesKey.encoded, clientAesKey.encoded,
            "Client→Server: AES key mismatch")

        // Client decrypts the message
        cipher.init(Cipher.DECRYPT_MODE, clientAesKey, GCMParameterSpec(128, iv))
        val decrypted = cipher.doFinal(ciphertext)
        assertContentEquals(plaintext, decrypted,
            "Client→Server: decrypted message mismatch")

        // === Direction 2: Server → Client ===
        // Client encapsulates an AES-256 key using the server's public key
        val encToServer = kem.newEncapsulator(serverKp.public)
            .encapsulate(0, 32, "AES")
        val clientAesKey2 = encToServer.key()

        // Client encrypts a reply
        val reply = "Hello from client, post-quantum secure!".toByteArray()
        cipher.init(Cipher.ENCRYPT_MODE, clientAesKey2)
        val iv2 = cipher.iv
        val ciphertext2 = cipher.doFinal(reply)

        // Server decapsulates and decrypts
        val serverAesKey2 = kem.newDecapsulator(serverKp.private)
            .decapsulate(encToServer.encapsulation(), 0, 32, "AES")
        assertContentEquals(clientAesKey2.encoded, serverAesKey2.encoded,
            "Server→Client: AES key mismatch")

        cipher.init(Cipher.DECRYPT_MODE, serverAesKey2, GCMParameterSpec(128, iv2))
        val decrypted2 = cipher.doFinal(ciphertext2)
        assertContentEquals(reply, decrypted2,
            "Server→Client: decrypted message mismatch")
    }
}
