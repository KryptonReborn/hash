package org.kotlincrypto.hash.blake2.blake2s

import org.kotlincrypto.hash.blake2.Blake2s
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@ExperimentalStdlibApi
class Blake2sNotKeyTest {
    data class NotKeyTestVector(
        val input: String,
        val output: String,
    )

    companion object {
        private val notKeyTestVectors = listOf(
            NotKeyTestVector(
                "blake2",
                "03ff98699d53d8c2680f98e2557bd96c2e4e1f4610fedabba50c266d0988c74b"
            ),
            NotKeyTestVector(
                "hello world",
                "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b"
            ),
            NotKeyTestVector(
                "verystrongandlongpassword",
                "d49abeeced4a85ee685a98a29a5ff3a46ad41bfdf6b8e5088716699a30c52265"
            ),
            NotKeyTestVector(
                "The quick brown fox jumps over the lazy dog",
                "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"
            ),
            NotKeyTestVector(
                "",
                "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
            ),
            NotKeyTestVector(
                "abc",
                "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
            ),
            NotKeyTestVector(
                "UPPERCASE",
                "8939a0dff88b336033bedf5da5ca536984c4e4865dc5d6ecea17e6c7e8df212a"
            ),
            NotKeyTestVector(
                "123456789",
                "7acc2dd21a2909140507f37396acce906864b5f118dfa766b107962b7a82a0d4"
            ),
        )
    }

    @Test
    fun testNotKey() {
        val blake2sNotKey = Blake2s()
        for (testVector in notKeyTestVectors) {
            val input: ByteArray = testVector.input.encodeToByteArray()
            for (j in input.indices) {
                blake2sNotKey.update(input[j])
            }

            val notKeyHash = ByteArray(32)
            blake2sNotKey.doFinal(notKeyHash, 0)

            assertEquals(testVector.output, notKeyHash.toHexString())
        }
    }

    @Test
    fun testLengthConstruction() {
        assertFailsWith<IllegalArgumentException> {
            Blake2s(-1)
        }.also {
            assertEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", it.message)
        }

        assertFailsWith<IllegalArgumentException> {
            Blake2s(9)
        }.also {
            assertEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", it.message)
        }

        assertFailsWith<IllegalArgumentException> {
            Blake2s(520)
        }.also {
            assertEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", it.message)
        }

        assertFailsWith<IllegalArgumentException> {
            Blake2s(null, -1, null, null)
        }.also {
            assertEquals("Invalid digest length (required: 1 - 32)", it.message)
        }

        assertFailsWith<IllegalArgumentException> {
            Blake2s(null, 33, null, null)
        }.also {
            assertEquals("Invalid digest length (required: 1 - 32)", it.message)
        }
    }

    @Test
    fun testNullKeyVsNotKey() {
        val abc: ByteArray = "abc".encodeToByteArray()

        for (i in 1..31) {
            val dig1 = Blake2s(i * 8)
            val dig2 = Blake2s(null, i, null, null)

            val out1 = ByteArray(i)
            val out2 = ByteArray(i)

            dig1.update(abc, 0, abc.size)
            dig2.update(abc, 0, abc.size)

            dig1.doFinal(out1, 0)
            dig2.doFinal(out2, 0)

            assertContentEquals(out1, out2)
        }
    }

    @Test
    fun testReset() {
        // Generate a non-zero key
        val key = ByteArray(32)
        for (i in key.indices) {
            key[i] = i.toByte()
        }
        // Generate some non-zero input longer than the key
        val input = ByteArray(key.size + 1)
        for (i in input.indices) {
            input[i] = i.toByte()
        }
        // Hash the input
        val digest = Blake2s(key)
        digest.update(input, 0, input.size)
        val hash = ByteArray(digest.digestSize)
        digest.doFinal(hash, 0)
        // Using a second instance, hash the input without calling doFinal()
        val digest1 = Blake2s(key)
        digest1.update(input, 0, input.size)
        // Reset the second instance and hash the input again
        digest1.reset()
        digest1.update(input, 0, input.size)
        val hash1 = ByteArray(digest.digestSize)
        digest1.doFinal(hash1, 0)
        // The hashes should be identical
        assertContentEquals(hash1, hash)
    }
}
