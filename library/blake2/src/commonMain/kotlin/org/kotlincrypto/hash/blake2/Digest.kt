package org.kotlincrypto.hash.blake2

/**
 * interface that a message Digest conforms to.
 */
public interface Digest {
    /**
     * return the algorithm name
     *
     * @return the algorithm name
     */
    public val algorithmName: String

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    public val digestSize: Int

    /**
     * Return the size in bytes of the internal buffer the digest applies its compression
     * function to.
     *
     * @return byte length of the digests internal buffer.
     */
    public val byteLength: Int

    /**
     * update the message digest with a single byte.
     *
     * @param input the input byte to be entered.
     */
    public fun update(input: Byte)

    /**
     * update the message digest with a block of bytes.
     *
     * @param input  the byte array containing the data.
     * @param offset the offset into the byte array where the data starts.
     * @param length the length of the data.
     */
    public fun update(input: ByteArray, offset: Int = 0, length: Int = input.size)

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     * Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    public fun doFinal(out: ByteArray, outOffset: Int): Int

    /**
     * Reset the digest back to it's initial state.
     * The key, the salt and the personal string will
     * remain for further computations.
     */
    public fun reset()

    /**
     * Overwrite the key
     * if it is no longer used (zeroization)
     */
    public fun clearKey()

    /**
     * Overwrite the salt (pepper) if it
     * is secret and no longer used (zeroization)
     */
    public fun clearSalt()
}