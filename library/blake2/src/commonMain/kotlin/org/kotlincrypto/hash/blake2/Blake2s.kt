package org.kotlincrypto.hash.blake2

import org.kotlincrypto.core.InternalKotlinCryptoApi
import org.kotlincrypto.core.digest.Digest
import org.kotlincrypto.core.digest.internal.DigestState

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
public class Blake2s : Digest {
    public companion object {
        // To use for Catenas H'
        private const val ROUNDS_IN_COMPRESS = 10

        // The size in bytes of the internal buffer the digest applies its compression
        private const val BLOCK_LENGTH_BYTES: Int = 64

        private const val MAX_DIGEST_LENGTH: Int = 32

        private const val ALGORITHM_NAME = "BLAKE2s"

        // BLAKE2s Initialization Vector:
        private val blake2s_IV = intArrayOf(
            0x6a09e667,
            -0x4498517b,
            0x3c6ef372,
            -0x5ab00ac6,
            0x510e527f,
            -0x64fa9774,
            0x1f83d9ab,
            0x5be0cd19
        )

        // Message word permutations:
        private val blake2s_sigma = arrayOf(
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

    // General parameters:
    private var digestLength = MAX_DIGEST_LENGTH // 1- 32 bytes
    private var keyLength = 0 // 0 - 32 bytes for keyed hashing for MAC
    private var salt: ByteArray? = null
    private var personalization: ByteArray? = null
    private var key: ByteArray? = null

    // Tree hashing parameters:
    // The Tree Hashing Mode is not supported but these are used for
    // the XOF implementation
    private var fanout = 1 // 0-255
    private var depth = 1 // 0-255
    private var leafLength = 0
    private var nodeOffset = 0L
    private var nodeDepth = 0
    private var innerHashLength = 0

    // whenever this buffer overflows, it will be processed in the compress() function.
    // For performance issues, long messages will not use this buffer.
    private var _buffer: ByteArray? = null

    // Position of last inserted byte:
    private var bufferPos = 0 // a value from 0 up to BLOCK_LENGTH_BYTES

    // Internal state, in the BLAKE2 paper it is called v
    private var internalState = IntArray(16)

    // State vector, in the BLAKE2 paper it is called h
    private var chainValue: IntArray? = null

    // holds last significant bits of counter (counts bytes)
    private var t0 = 0

    // counter: Length up to 2^64 are supported
    private var t1 = 0

    // finalization flag, for last block: ~0
    private var f0 = 0

    @OptIn(InternalKotlinCryptoApi::class)
    public constructor(digest: Blake2s) : super(ALGORITHM_NAME, BLOCK_LENGTH_BYTES, digest.digestLength) {
        bufferPos = digest.bufferPos
        _buffer = digest._buffer?.copyOf()
        keyLength = digest.keyLength
        key = digest.key?.copyOf()
        digestLength = digest.digestLength
        internalState = internalState.copyOf()
        chainValue = digest.chainValue?.copyOf()
        t0 = digest.t0
        t1 = digest.t1
        f0 = digest.f0
        salt = digest.salt?.copyOf()
        personalization = digest.personalization?.copyOf()
        fanout = digest.fanout
        depth = digest.depth
        leafLength = digest.leafLength
        nodeOffset = digest.nodeOffset
        nodeDepth = digest.nodeDepth
        innerHashLength = digest.innerHashLength
    }

    /**
     * BLAKE2s-256 for hashing.
     *
     * @param digestBits the desired digest length in bits. Must be a multiple of 8 and less than 256.
     */
    @OptIn(InternalKotlinCryptoApi::class)
    public constructor(digestBits: Int = 256) : super(ALGORITHM_NAME, BLOCK_LENGTH_BYTES, digestBits / 8) {
        require(!(digestBits < 8 || digestBits > 256 || digestBits % 8 != 0)) {
            "BLAKE2s digest bit length must be a multiple of 8 and not greater than 256"
        }
        digestLength = digestBits / 8
        init(null, null, null)
    }

    /**
     * BLAKE2s for authentication ("Prefix-MAC mode").
     *
     * After calling the doFinal() method, the key will remain to be used for
     * further computations of this instance.
     *
     * The key can be overwritten using the clearKey() method.
     *
     * @param key a key up to 32 bytes or null
     */
    @OptIn(InternalKotlinCryptoApi::class)
    public constructor(key: ByteArray?) : super(ALGORITHM_NAME, BLOCK_LENGTH_BYTES, MAX_DIGEST_LENGTH) {
        init(null, null, key)
    }

    /**
     * BLAKE2s with key, required digest length, salt and personalization.
     *
     * After calling the doFinal() method, the key, the salt and the personal
     * string will remain and might be used for further computations with this
     * instance.
     *
     * The key can be overwritten using the clearKey() method, the
     * salt (pepper) can be overwritten using the clearSalt() method.
     *
     * @param key             a key up to 32 bytes or null
     * @param digestLength     from 1 up to 32 bytes
     * @param salt            8 bytes or null
     * @param personalization 8 bytes or null
     */
    @OptIn(InternalKotlinCryptoApi::class)
    public constructor(
        key: ByteArray?,
        digestLength: Int,
        salt: ByteArray?,
        personalization: ByteArray?
    ) : super(ALGORITHM_NAME, BLOCK_LENGTH_BYTES, digestLength) {
        require(!(digestLength < 1 || digestLength > MAX_DIGEST_LENGTH)) { "Invalid digest length (required: 1 - 32)" }
        this.digestLength = digestLength
        init(salt, personalization, key)
    }

    override fun updateDigest(input: Byte) {
        // process the buffer if full else add to buffer:
        val remainingLength: Int = BLOCK_LENGTH_BYTES - bufferPos // left bytes of buffer
        if (remainingLength == 0) { // full buffer
            t0 += BLOCK_LENGTH_BYTES
            if (t0 == 0) { // if message > 2^32
                t1++
            }
            compress(_buffer!!, 0)
            _buffer?.fill(0) // clear buffer
            _buffer!![0] = input
            bufferPos = 1
        } else {
            _buffer!![bufferPos] = input
            bufferPos++
        }
    }

    override fun updateDigest(
        input: ByteArray,
        offset: Int,
        len: Int,
    ) {
        if (len == 0) {
            return
        }
        var remainingLength = 0 // left bytes of buffer
        if (bufferPos != 0) {
            // commenced, incomplete buffer
            // complete the buffer:
            remainingLength = BLOCK_LENGTH_BYTES - bufferPos
            if (remainingLength < len) { // full buffer + at least 1 byte
                input.copyInto(_buffer!!, bufferPos, offset, offset + remainingLength)
                t0 += BLOCK_LENGTH_BYTES
                if (t0 == 0) { // if message > 2^32
                    t1++
                }
                compress(_buffer!!, 0)
                bufferPos = 0
                _buffer?.fill(0) // clear buffer
            } else {
                input.copyInto(_buffer!!, bufferPos, offset, offset + len)
                bufferPos += len
                return
            }
        }

        // process blocks except last block (also if last block is full)
        val blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES
        var messagePos: Int = offset + remainingLength
        while (messagePos < blockWiseLastPos) {
            // block wise 64 bytes
            // without buffer:
            t0 += BLOCK_LENGTH_BYTES
            if (t0 == 0) {
                t1++
            }
            compress(input, messagePos)
            messagePos += BLOCK_LENGTH_BYTES
        }

        // fill the buffer with left bytes, this might be a full block
        input.copyInto(_buffer!!, 0, messagePos, offset + len)
        bufferPos += offset + len - messagePos
    }

    override fun digest(bitLength: Long, bufferOffset: Int, buffer: ByteArray): ByteArray {
        val out = ByteArray(digestLength)
        f0 = -0x1
        t0 += bufferPos
        // bufferPos may be < 64, so (t0 == 0) does not work
        // for 2^32 < message length > 2^32 - 63
        if (t0 < 0 && bufferPos > -t0) {
            t1++
        }
        compress(_buffer!!, 0)
        _buffer?.fill(0) // Holds eventually the key if input is null
        internalState.fill(0)
        var i = 0
        while (i < chainValue!!.size && i * 4 < digestLength) {
            val bytes = ByteArray(4)
            encodeLEInt(chainValue!![i], bytes, 0)
            if (i * 4 < digestLength - 4) {
                bytes.copyInto(out, bufferOffset + i * 4, 0, 4)
            } else {
                bytes.copyInto(out, bufferOffset + i * 4, 0, digestLength - i * 4)
            }
            i++
        }
        chainValue?.fill(0)
        reset()
        return out
    }

    override fun resetDigest() {
        bufferPos = 0
        f0 = 0
        t0 = 0
        t1 = 0
        chainValue = null
        _buffer?.fill(0)
        if (key != null) {
            key!!.copyInto(_buffer!!, 0, 0, key!!.size)
            bufferPos = BLOCK_LENGTH_BYTES // zero padding
        }
        init(salt, personalization, key)
    }

    override fun copy(state: DigestState): Digest = Blake2s(this)

    /**
     * Overwrite the key
     * if it is no longer used (zeroization)
     */
    public fun clearKey() {
        if (key != null) {
            key?.fill(0)
            _buffer?.fill(0)
        }
    }

    /**
     * Overwrite the salt (pepper) if it
     * is secret and no longer used (zeroization)
     */
    public fun clearSalt() {
        if (salt != null) {
            salt?.fill(0)
        }
    }

    override fun compress(input: ByteArray, offset: Int) {
        initInternalState()
        val m = IntArray(16)
        for (j in 0..15) {
            m[j] = decodeLEInt(input, offset + j * 4)
        }
        for (round in 0 until ROUNDS_IN_COMPRESS) {
            // G apply to columns of internalState:
            // m[blake2s_sigma[round][2 * blockPos]] /+1
            g(m[blake2s_sigma[round][0].toInt()], m[blake2s_sigma[round][1].toInt()], 0, 4, 8, 12)
            g(m[blake2s_sigma[round][2].toInt()], m[blake2s_sigma[round][3].toInt()], 1, 5, 9, 13)
            g(m[blake2s_sigma[round][4].toInt()], m[blake2s_sigma[round][5].toInt()], 2, 6, 10, 14)
            g(m[blake2s_sigma[round][6].toInt()], m[blake2s_sigma[round][7].toInt()], 3, 7, 11, 15)
            // G apply to diagonals of internalState:
            g(m[blake2s_sigma[round][8].toInt()], m[blake2s_sigma[round][9].toInt()], 0, 5, 10, 15)
            g(m[blake2s_sigma[round][10].toInt()], m[blake2s_sigma[round][11].toInt()], 1, 6, 11, 12)
            g(m[blake2s_sigma[round][12].toInt()], m[blake2s_sigma[round][13].toInt()], 2, 7, 8, 13)
            g(m[blake2s_sigma[round][14].toInt()], m[blake2s_sigma[round][15].toInt()], 3, 4, 9, 14)
        }

        // update chain values:
        for (position in chainValue!!.indices) {
            chainValue!![position] = chainValue!![position] xor internalState[position] xor internalState[position + 8]
        }
    }

    // initialize the digest's parameters
    private fun init(salt: ByteArray?, personalization: ByteArray?, key: ByteArray?) {
        _buffer = ByteArray(BLOCK_LENGTH_BYTES)
        if (key != null && key.isNotEmpty()) {
            require(key.size <= MAX_DIGEST_LENGTH) { "Keys > 32 bytes are not supported" }
            this.key = key.copyInto(ByteArray(key.size), 0, 0, key.size)
            keyLength = key.size
            key.copyInto(_buffer!!, 0, 0, key.size)
            bufferPos = BLOCK_LENGTH_BYTES // zero padding
        }
        if (chainValue == null) {
            chainValue = IntArray(8)
            chainValue!![0] =
                (blake2s_IV[0] xor (digestLength or (keyLength shl 8) or (fanout shl 16 or (depth shl 24))))
            chainValue!![1] = blake2s_IV[1] xor leafLength
            val nofHi = (nodeOffset shr 32).toInt()
            val nofLo = nodeOffset.toInt()
            chainValue!![2] = blake2s_IV[2] xor nofLo
            chainValue!![3] = blake2s_IV[3] xor (nofHi or (nodeDepth shl 16) or (innerHashLength shl 24))
            chainValue!![4] = blake2s_IV[4]
            chainValue!![5] = blake2s_IV[5]
            if (salt != null) {
                require(salt.size == 8) { "Salt length must be exactly 8 bytes" }
                this.salt = salt.copyInto(ByteArray(8), 0, 0, salt.size)
                chainValue!![4] = chainValue!![4] xor decodeLEInt(salt, 0)
                chainValue!![5] = chainValue!![5] xor decodeLEInt(salt, 4)
            }
            chainValue!![6] = blake2s_IV[6]
            chainValue!![7] = blake2s_IV[7]
            if (personalization != null) {
                require(personalization.size == 8) { "Personalization length must be exactly 8 bytes" }
                this.personalization = personalization.copyInto(ByteArray(8), 0, 0, personalization.size)
                chainValue!![6] = chainValue!![6] xor decodeLEInt(personalization, 0)
                chainValue!![7] = chainValue!![7] xor decodeLEInt(personalization, 4)
            }
        }
    }

    private fun initInternalState() {
        // initialize v:
        chainValue!!.copyInto(internalState, 0, 0, chainValue!!.size)
        blake2s_IV.copyInto(internalState, chainValue!!.size, 0, 4)

        internalState[12] = t0 xor blake2s_IV[4]
        internalState[13] = t1 xor blake2s_IV[5]
        internalState[14] = f0 xor blake2s_IV[6]
        internalState[15] = blake2s_IV[7] // ^ f1 with f1 = 0
    }

    private fun g(m1: Int, m2: Int, posA: Int, posB: Int, posC: Int, posD: Int) {
        internalState[posA] = internalState[posA] + internalState[posB] + m1
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(16)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(12)
        internalState[posA] = internalState[posA] + internalState[posB] + m2
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(8)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(7)
    }

    /**
     * Decode a 32-bit little-endian word from the array [buf]
     * at offset [off].
     *
     * @param buf the source buffer
     * @param off the source offset
     * @return the decoded value
     */
    private inline fun decodeLEInt(buf: ByteArray, off: Int): Int {
        return (buf[off + 3].toInt() and 0xFF shl 24) or
                (buf[off + 2].toInt() and 0xFF shl 16) or
                (buf[off + 1].toInt() and 0xFF shl 8) or
                (buf[off].toInt() and 0xFF)
    }

    /**
     * Encode the 32-bit word [value] into the array
     * [buf] at offset [off], in little-endian
     * convention (least significant byte first).
     *
     * @param value the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private fun encodeLEInt(value: Int, buf: ByteArray, off: Int) {
        buf[off + 0] = value.toByte()
        buf[off + 1] = (value ushr 8).toByte()
        buf[off + 2] = (value ushr 16).toByte()
        buf[off + 3] = (value ushr 24).toByte()
    }
}
