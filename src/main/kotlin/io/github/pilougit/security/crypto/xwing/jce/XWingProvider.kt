package io.github.pilougit.security.crypto.xwing.jce

import java.security.Provider

class XWingProvider : Provider("XWing", "1.0", "X-Wing KEM Provider") {
    init {
        put("KEM.X-Wing", XWingKEMSpi::class.java.name)
        put("KeyPairGenerator.X-Wing", XWingKeyPairGeneratorSpi::class.java.name)
    }
}
