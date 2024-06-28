package org.kotlincrypto.hash.blake2

import org.kotlincrypto.core.InternalKotlinCryptoApi
import org.kotlincrypto.core.digest.Digest
import org.kotlincrypto.core.digest.internal.DigestState

@OptIn(InternalKotlinCryptoApi::class)
public abstract class Blake2(
    algorithmName: String,
    private val blockLengthBytes: Int,
    digestBits: Int
) : Digest(algorithmName, blockLengthBytes, digestBits / 8) {
    // Internal state, in the BLAKE2 paper it is called v
    private val internalState: Array<Blake2Word> = Array(16) { createWord(0L) }

    // To use for Catenas H'
    protected abstract val roundsInCompress: Int
    protected abstract val sizeBytes: Int
    protected abstract val r1: Int
    protected abstract val r2: Int
    protected abstract val r3: Int
    protected abstract val r4: Int

    // BLAKE Initialization Vector:
    protected abstract val blakeIV: Array<Blake2Word>

    // Message word permutations:
    protected abstract val blakeSigma: Array<ByteArray>

    // State vector, in the BLAKE2 paper it is called h
    protected var chainValue: Array<Blake2Word>? = null

    // holds last significant bits of counter (counts bytes)
    protected lateinit var t0: Blake2Word

    // finalization flag, for last block: ~0
    protected lateinit var f0: Blake2Word

    override fun digest(bitLength: Long, bufferOffset: Int, buffer: ByteArray): ByteArray {
        val digestLength = digestLength()
        val out = ByteArray(digestLength)
        f0 = createWord(-0x1L)
        t0 = createWord(bitLength / 8)

        compress(buffer, 0)
        internalState.fill(createWord(0L))
        var i = 0
        while (i < chainValue!!.size && i * sizeBytes < digestLength) {
            val bytes = chainValue!![i].toLittleEndian()
            if (i * sizeBytes < digestLength - sizeBytes) {
                bytes.copyInto(out, i * sizeBytes, 0, sizeBytes)
            } else {
                bytes.copyInto(out, i * sizeBytes, 0, digestLength - i * sizeBytes)
            }
            i++
        }
        chainValue?.fill(createWord(0L))
        reset()
        return out
    }

    override fun resetDigest() {
        f0 = createWord(0L)
        t0 = createWord(0L)
        chainValue = null
        initChainValue()
    }

    abstract override fun copy(state: DigestState): Digest

    override fun compress(input: ByteArray, offset: Int) {
        if (input.size > blockLengthBytes) t0 = createWord(blockLengthBytes.toLong())
        initInternalState()
        val m = createM(input, offset)
        for (round in 0 until roundsInCompress) {
            // G apply to columns of internalState
            // :m[blake2b_sigma[round][2 * blockPos]] /+1
            g(m[blakeSigma[round][0].toInt()], m[blakeSigma[round][1].toInt()], 0, 4, 8, 12)
            g(m[blakeSigma[round][2].toInt()], m[blakeSigma[round][3].toInt()], 1, 5, 9, 13)
            g(m[blakeSigma[round][4].toInt()], m[blakeSigma[round][5].toInt()], 2, 6, 10, 14)
            g(m[blakeSigma[round][6].toInt()], m[blakeSigma[round][7].toInt()], 3, 7, 11, 15)
            // G apply to diagonals of internalState:
            g(m[blakeSigma[round][8].toInt()], m[blakeSigma[round][9].toInt()], 0, 5, 10, 15)
            g(m[blakeSigma[round][10].toInt()], m[blakeSigma[round][11].toInt()], 1, 6, 11, 12)
            g(m[blakeSigma[round][12].toInt()], m[blakeSigma[round][13].toInt()], 2, 7, 8, 13)
            g(m[blakeSigma[round][14].toInt()], m[blakeSigma[round][15].toInt()], 3, 4, 9, 14)
        }

        // update chain values:
        for (position in chainValue!!.indices) {
            chainValue!![position] = chainValue!![position] xor internalState[position] xor internalState[position + 8]
        }
    }

    protected fun initChainValue() {
        if (chainValue == null) {
            chainValue = Array(8) { createWord(0L) }
            blakeIV.copyInto(chainValue!!)
            chainValue!![0] = (blakeIV[0] xor (createWord(digestLength().toLong()) or createWord(0x1010000L)))
        }
    }

    private fun initInternalState() {
        // initialize v:
        chainValue!!.copyInto(internalState, 0, 0, chainValue!!.size)
        blakeIV.copyInto(internalState, chainValue!!.size, 0, 4)

        internalState[12] = t0 xor blakeIV[4]
        internalState[13] = createWord(0L) xor blakeIV[5]
        internalState[14] = f0 xor blakeIV[6]
        internalState[15] = blakeIV[7]
    }

    private fun g(m1: Blake2Word, m2: Blake2Word, posA: Int, posB: Int, posC: Int, posD: Int) {
        internalState[posA] = internalState[posA] + internalState[posB] + m1
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(r1)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(r2)
        internalState[posA] = internalState[posA] + internalState[posB] + m2
        internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(r3)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(r4)
    }

    protected abstract fun createM(input: ByteArray, offset: Int): Array<Blake2Word>

    protected abstract fun createWord(value: Long): Blake2Word
}
