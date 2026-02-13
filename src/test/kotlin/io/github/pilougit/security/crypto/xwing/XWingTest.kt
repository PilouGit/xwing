package io.github.pilougit.security.crypto.xwing

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.apache.commons.codec.binary.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

class XWingTest {

    data class TestVector(
        val seed: String,
        val sk: String,
        val pk: String,
        val eseed: String,
        val ct: String,
        val ss: String
    )

    private val testVectors: List<TestVector> by lazy {
        val json = this::class.java.getResource("/test-vectors.json")!!.readText()
        Gson().fromJson(json, object : TypeToken<List<TestVector>>() {}.type)
    }

    @Test
    fun `GenerateKeyPairDerand produces expected pk`() {
        for ((i, tv) in testVectors.withIndex()) {
            val seed = Hex.decodeHex(tv.seed)
            val expectedPk = Hex.decodeHex(tv.pk)

            val keyPair = XWing.generateKeyPairDerand(seed)

            assertContentEquals(expectedPk, keyPair.pk,
                "Test vector ${i + 1}: pk mismatch")
            assertContentEquals(seed, keyPair.sk,
                "Test vector ${i + 1}: sk mismatch")
        }
    }

    @Test
    fun `EncapsulateDeRand produces expected ct and ss`() {
        for ((i, tv) in testVectors.withIndex()) {
            val pk = Hex.decodeHex(tv.pk)
            val eseed = Hex.decodeHex(tv.eseed)
            val expectedCt = Hex.decodeHex(tv.ct)
            val expectedSs = Hex.decodeHex(tv.ss)

            val result = XWing.encapsulateDeRand(pk, eseed)

            assertContentEquals(expectedCt, result.encapsulation,
                "Test vector ${i + 1}: ct mismatch")
            assertContentEquals(expectedSs, result.secret,
                "Test vector ${i + 1}: ss mismatch")
        }
    }

    @Test
    fun `Decapsulate produces expected ss`() {
        for ((i, tv) in testVectors.withIndex()) {
            val ct = Hex.decodeHex(tv.ct)
            val sk = Hex.decodeHex(tv.sk)
            val expectedSs = Hex.decodeHex(tv.ss)

            val ss = XWing.decapsulate(ct, sk)

            assertContentEquals(expectedSs, ss,
                "Test vector ${i + 1}: ss mismatch")
        }
    }

    @Test
    fun `Encapsulate and Decapsulate round-trip`() {
        val keyPair = XWing.generateKeyPair()
        val encapsulated = XWing.encapsulate(keyPair.pk)
        val ss = XWing.decapsulate(encapsulated.encapsulation, keyPair.sk)

        assertContentEquals(encapsulated.secret, ss,
            "Round-trip: shared secret mismatch")
    }
}
