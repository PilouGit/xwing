package io.github.pilougit.security.crypto.xwing

data class ExpandedDecapsulationKey(
    val skM: ByteArray,
    val skX: ByteArray,
    val pkM: ByteArray,
    val pkX: ByteArray,
)
