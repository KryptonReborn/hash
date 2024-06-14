package org.kotlincrypto.hash.blake2.blake2s

import org.kotlincrypto.hash.blake2.Blake2s
import kotlin.test.Test
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class Blake2sKeyedTest {
    data class KeyedTestVector(
        val input: String,
        val key: String,
        val output: String,
    )

    companion object {
        private val keyedTestVectors by lazy {
            listOf(
                // Vectors from BLAKE2 website: https://blake2.net/blake2s-test.txt
                KeyedTestVector(
                    "",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
                ),

                KeyedTestVector(
                    "00",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
                ),

                KeyedTestVector(
                    "0001",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
                ),

                KeyedTestVector(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "172ffc67153d12e0ca76a8b6cd5d4731885b39ce0cac93a8972a18006c8b8baf",
                ),

                KeyedTestVector(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "4f8ce1e51d2fe7f24043a904d898ebfc91975418753413aa099b795ecb35cedb",
                ),

                KeyedTestVector(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd",
                )
            )
        }
    }

    @Test
    fun testKeyed() {
        val blake2sKeyed = Blake2s(keyedTestVectors[0].key.hexToByteArray())
        for (testVector in keyedTestVectors) {
            val input: ByteArray = testVector.input.hexToByteArray()
            val keyedHash = blake2sKeyed.digest(input)

            assertEquals(testVector.output, keyedHash.toHexString())
        }
    }
}
