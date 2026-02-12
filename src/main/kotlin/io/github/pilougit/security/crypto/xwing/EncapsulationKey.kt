package io.github.pilougit.security.crypto.xwing

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters

data class EncapsulationKey
    (
    val skM: MLKEMPublicKeyParameters,
    val skX: X25519PublicKeyParameters
)
