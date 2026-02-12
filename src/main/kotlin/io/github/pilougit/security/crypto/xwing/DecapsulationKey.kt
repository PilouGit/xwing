package io.github.pilougit.security.crypto.xwing

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters

data class DecapsulationKey
    (
    val skM: MLKEMPrivateKeyParameters,
    val skX: X25519PrivateKeyParameters
)
