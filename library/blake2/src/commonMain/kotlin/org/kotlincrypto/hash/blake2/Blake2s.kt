package org.kotlincrypto.hash.blake2

import org.kotlincrypto.core.digest.Digest
import org.kotlincrypto.core.digest.internal.DigestState
import org.kotlincrypto.endians.LittleEndian.Companion.bytesToInt

/*
  The BLAKE2 cryptographic hash function was designed by Jean-
  Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
  Winnerlein.
  Reference Implementation and Description can be found at: https://blake2.net/
  RFC: https://tools.ietf.org/html/rfc7693
  This implementation does not support the Tree Hashing Mode.
  For unkeyed hashing, developers adapting BLAKE2 to ASN.1 - based
  message formats SHOULD use the OID tree at x = 1.3.6.1.4.1.1722.12.2.
         Algorithm     | Target | Collision | Hash | Hash ASN.1 |
            Identifier |  Arch  |  Security |  nn  | OID Suffix |
        ---------------+--------+-----------+------+------------+
         id-blake2s128 | 32-bit |   2**64   |  16  |   x.2.4    |
         id-blake2s160 | 32-bit |   2**80   |  20  |   x.2.5    |
         id-blake2s224 | 32-bit |   2**112  |  28  |   x.2.7    |
         id-blake2s256 | 32-bit |   2**128  |  32  |   x.2.8    |
        ---------------+--------+-----------+------+------------+
 */

/**
 * Implementation of the cryptographic hash function BLAKE2s.
 *
 *
 * BLAKE2s offers a built-in keying mechanism to be used directly
 * for authentication ("Prefix-MAC") rather than a HMAC construction.
 *
 *
 * BLAKE2s offers a built-in support for a salt for randomized hashing
 * and a personal string for defining a unique hash function for each application.
 *
 *
 * BLAKE2s is optimized for 32-bit platforms and produces digests of any size
 * between 1 and 32 bytes.
 */
public class Blake2s : Blake2 {
    public companion object {
        private const val MAX_DIGEST_BITS_LENGTH = 256
        private const val BLOCK_LENGTH_BYTES: Int = 64
        private const val ALGORITHM_NAME = "BLAKE2s"

        /**
         * Hash [input] as Blake2s-128 .
         * @return hashed [ByteArray] with size = 16.
         */
        public fun blake2sHash128(input: ByteArray): ByteArray {
            val blake2s = Blake2s(128)
            blake2s.update(input)
            return blake2s.digest()
        }
    }

    override val roundsInCompress: Int = 10
    override val sizeBytes: Int = Int.SIZE_BYTES
    override val r1: Int = 16
    override val r2: Int = 12
    override val r3: Int = 8
    override val r4: Int = 7

    override val blakeIV: Array<Blake2Word>
        get() = arrayOf(
            Blake2Word.Blake2sWord(0x6a09e667),
            Blake2Word.Blake2sWord(-0x4498517b),
            Blake2Word.Blake2sWord(0x3c6ef372),
            Blake2Word.Blake2sWord(-0x5ab00ac6),
            Blake2Word.Blake2sWord(0x510e527f),
            Blake2Word.Blake2sWord(-0x64fa9774),
            Blake2Word.Blake2sWord(0x1f83d9ab),
            Blake2Word.Blake2sWord(0x5be0cd19),
        )
    override val blakeSigma: Array<ByteArray>
        get() = arrayOf(
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
        )

    public constructor(digestBits: Int = MAX_DIGEST_BITS_LENGTH) : super(
        ALGORITHM_NAME,
        BLOCK_LENGTH_BYTES,
        digestBits
    ) {
        require(digestBits in 8..MAX_DIGEST_BITS_LENGTH && digestBits % 8 == 0) {
            "$ALGORITHM_NAME digest bit length must be a multiple of 8 and not greater than $MAX_DIGEST_BITS_LENGTH"
        }
        t0 = createWord(0L)
        f0 = createWord(0L)
        initChainValue()
    }

    public constructor(digest: Blake2s) : super(ALGORITHM_NAME, BLOCK_LENGTH_BYTES, digest.digestLength()) {
        chainValue = digest.chainValue?.copyOf()
        t0 = digest.t0
        f0 = digest.f0
    }

    override fun copy(state: DigestState): Digest = Blake2s(this)

    override fun createM(input: ByteArray, offset: Int): Array<Blake2Word> {
        val m = Array<Blake2Word>(16) { Blake2Word.Blake2sWord(0) }
        for (j in 0..15) {
            var startIndex = offset + j * sizeBytes
            m[j] = Blake2Word.Blake2sWord(
                bytesToInt(
                    input[startIndex],
                    input[++startIndex],
                    input[++startIndex],
                    input[++startIndex],
                )
            )
        }
        return m
    }

    override fun createWord(value: Long): Blake2Word = Blake2Word.Blake2sWord(value.toInt())
}
