package io.github.pilougit.security.crypto.xwing

import io.github.pilougit.security.crypto.xwing.primitive.Primitives
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.prng.FixedSecureRandom
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl
import java.security.SecureRandom

object XWing {

    /**
     * def expandDecapsulationKey(sk):
     *   expanded = SHAKE256(sk, 96*8) # expand sk to 96 bytes using SHAKE256
     *   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
     *   sk_X = expanded[64:96]
     *   pk_X = X25519(sk_X, X25519_BASE)
     *   return (sk_M, sk_X, pk_M, pk_X)
     */
    fun expandDecapsulationKey(sk:ByteArray, useDerivedSeed: Boolean = false): ExpandedDecapsulationKey {
        val expanded=Primitives.shake256(sk,96)
        val asymmetricKeyPair=Primitives.keyGen(expanded.copyOfRange(0, 32),
            expanded.copyOfRange(32, 64),useDerivedSeed)
        val skX = expanded.copyOfRange(64,96)

        val pkX = Primitives.x25519(skX, Primitives.X25519_BASE)
        val pkM = asymmetricKeyPair.public as MLKEMPublicKeyParameters
        val skM = asymmetricKeyPair.private as MLKEMPrivateKeyParameters

        return ExpandedDecapsulationKey(skM.encoded,
            skX, pkM.encoded,pkX)
    }
    /**
     *  EncapsulateDerand(pk, eseed):
     *      pk_M = pk[0:1184]
     *      pk_X = pk[1184:1216]
     *      ek_X = eseed[32:64]
     *      ct_X = X25519(ek_X, X25519_BASE)
     *      ss_X = X25519(ek_X, pk_X)
     *      (ss_M, ct_M) = ML-KEM-768.Encaps_internal(pk_M, eseed[0:32])
     *      ss = Combiner(ss_M, ss_X, ct_X, pk_X)
     *      ct = concat(ct_M, ct_X)
     *      return (ss, ct)
     */
    fun encapsulateDeRand(pk: ByteArray,eseed:ByteArray): SecretWithEncapsulation {
        val pkM = pk.copyOfRange(0,1184)
        val pkX=pk.copyOfRange(1184,1216)
        val ekX = eseed.copyOfRange(32,64)
        val ctX= Primitives.x25519(ekX, Primitives.X25519_BASE)
        val ssX= Primitives.x25519(ekX,pkX)
        val secretWithEncapsulation=Primitives.mlkem768Encaps(pkM, FixedSecureRandom(eseed.copyOfRange(0,32)))
        val ss= Primitives.combiner(secretWithEncapsulation.secret,
            ssX,ctX,pkX)
        val ct=secretWithEncapsulation.encapsulation+ctX
        return SecretWithEncapsulationImpl(ss, ct)
    }
    fun encapsulate(pk: ByteArray): SecretWithEncapsulation {
        val secureRandom= SecureRandom.getInstanceStrong()
        val eseed= ByteArray(64)
        secureRandom.nextBytes(eseed)
        return encapsulateDeRand(pk,eseed)
    }
    /**
     * def Decapsulate(ct, sk):
     *      (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
     *      ct_M = ct[0:1088]
     *      ct_X = ct[1088:1120]
     *      ss_M = ML-KEM-768.Decapsulate(ct_M, sk_M)
     *      ss_X = X25519(sk_X, ct_X)
     *      return Combiner(ss_M, ss_X, ct_X, pk_X)
     */
    fun decapsulate(ct: ByteArray,sk: ByteArray, useDerivedSeed: Boolean = false): ByteArray {
        val expandedDecapsulationKey=expandDecapsulationKey(sk,useDerivedSeed)
        val ctM=ct.copyOfRange(0,1088)
        val ctX=ct.copyOfRange(1088,1120)
        val ssM= Primitives.mlkem768Decap(ctM,expandedDecapsulationKey.skM)
        val ssX= Primitives.x25519(expandedDecapsulationKey.skX,ctX)
        return Primitives.combiner(ssM,ssX,ctX,expandedDecapsulationKey.pkX)
    }

        /**
     * def GenerateKeyPair():
     *   sk = random(32)
     *   (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
     *   return sk, concat(pk_M, pk_X)
     */
    fun generateKeyPair(): XWingKeyPair {
        val secureRandom= SecureRandom.getInstanceStrong()
        val sk= ByteArray(32)
            secureRandom.nextBytes(sk)
            return generateKeyPairDerand(sk)

        }
    fun generateKeyPairDerand(sk: ByteArray,useDerivedSeed: Boolean = false): XWingKeyPair {
        val expandedDecapsulationKey=expandDecapsulationKey(sk,useDerivedSeed)
        return XWingKeyPair(sk,expandedDecapsulationKey.pkM+expandedDecapsulationKey.pkX)


    }
}