package org.kotlincrypto.hash.blake2

import org.kotlincrypto.endians.LittleEndian
import org.kotlincrypto.endians.LittleEndian.Companion.toLittleEndian

public sealed class Blake2Word {
    internal abstract operator fun plus(other: Blake2Word): Blake2Word
    internal abstract infix fun or(other: Blake2Word): Blake2Word
    internal abstract infix fun xor(other: Blake2Word): Blake2Word
    internal abstract fun rotateRight(bits: Int): Blake2Word
    internal abstract fun toLittleEndian(): LittleEndian

    internal data class Blake2sWord(val value: Int) : Blake2Word() {
        override operator fun plus(other: Blake2Word): Blake2Word = when (other) {
            is Blake2sWord -> Blake2sWord(this.value + other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override infix fun or(other: Blake2Word): Blake2Word = when (other) {
            is Blake2sWord -> Blake2sWord(this.value or other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override infix fun xor(other: Blake2Word): Blake2Word = when (other) {
            is Blake2sWord -> Blake2sWord(this.value xor other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override fun rotateRight(bits: Int): Blake2Word = Blake2sWord(value.rotateRight(bits))
        override fun toLittleEndian(): LittleEndian = value.toLittleEndian()
    }

    internal data class Blake2bWord(val value: Long) : Blake2Word() {
        override operator fun plus(other: Blake2Word): Blake2Word = when (other) {
            is Blake2bWord -> Blake2bWord(this.value + other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override infix fun or(other: Blake2Word): Blake2Word = when (other) {
            is Blake2bWord -> Blake2bWord(this.value or other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override infix fun xor(other: Blake2Word): Blake2Word = when (other) {
            is Blake2bWord -> Blake2bWord(this.value xor other.value)
            else -> throw IllegalArgumentException("Incompatible types")
        }

        override fun rotateRight(bits: Int): Blake2Word = Blake2bWord(value.rotateRight(bits))
        override fun toLittleEndian(): LittleEndian = value.toLittleEndian()
    }
}
