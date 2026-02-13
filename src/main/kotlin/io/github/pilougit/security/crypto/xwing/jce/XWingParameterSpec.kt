package io.github.pilougit.security.crypto.xwing.jce

import java.security.spec.AlgorithmParameterSpec

data class XWingParameterSpec(
    val useDerivedSeed: Boolean = false
) : AlgorithmParameterSpec
