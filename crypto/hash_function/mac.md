## Message Authentication Code

1. Provides integrity and authenticity both of a message.

1. Tag size should be minimum 128 bit means 2^128 operations to find a collision with a 50% probability.

   1. here key is unknown therefore offline attack is not possible.

1. MAC must be `verifited` in constant time to prevent timing attack.

   


### Keyed Hashing Algorithms

1. Siphash
   1. It is used to prevent hash flooding attack on non-crypto hash functions.
   2. Mainly designed for the short authentication tag with a random key generated at the starting of the program.
      1. produce 64 and 128 bit output both
   3. Improved performance and efficient than HMAC

2. BLAKE - two varients BLAKE2b , BLAKE2s
   1. BLAKE2b is more efficient on 64-bit CPUs and BLAKE2s is more efficient on 8-bit, 16-bit, or 32-bit CPUs.
   2. BLAKE2b and BLAKE2s produce different outputs even if the output length is the same.
   3. BLAKE2 supports
      1. **keyed mode** (a faster and simpler replacement for HMAC.
      2. Randomized hashing by using salt and personalization
   4. It creates authenticated tag / digest by using `salt` and `personalization` parameter. Thus it is faster and simpler replacement for HMAC.
   5. In BLAKE2b: both parameter's length = 16 bytes
   6. In BLAKE2s: both parameter's length = 8 bytes
   7. however, for convenience, python `hashlib` implementation accepts byte strings of any size up to the specified length. 
   8. If the length of the parameter is less than specified, it is padded with zeros, thus, for example, `b'salt'` and `b'salt\x00'` is the same value. (This is not the case for *key*.)
   9. BLAKE2 is fast in software because it exploits features of modern CPUs, namely instruction-level parallelism, SIMD instruction set extensions, and multiple cores. It is also faster than sha1, md5 and sha3.
   10. BLAKE, relies on a core algorithm borrowed from the ChaCha stream cipher 
   11. As a practical example, a web application can symmetrically sign cookies sent to users and later verify them to make sure they weren’t tampered with.

3. HMAC - hash based MAC

   1. it is customizable means the size the authN tag is dictated by the hash function used.
   1. creates two keys from the main key using ipad and opad before concatinate with message.
      1. func(K1 || message) => H1
      2. func(K2 || H1) => FINAL hash
   1. Size of the autn tag is dictate by the hash function used.
   1. Key/ secret is concatinated twice => H(k || message || k)
   1. Therefore it is not impacted by hash length extension attack.

4. KMAC - a wrapper around cSHAKE

   1. SHAKE and cSHAKE uses the same construction used by SHA3.
      1. SHA3 does not suffer from hash length extention attack.
   2. XOF exception: Shorter hash outputs are NOT prefixes of longer hash outputs. one byte changes in length produces entirely different hash.

5. Followings are not recommended 

   1. SHA2(`message` || `key`) 
      1. Append the secret at the end of the message to avoid hash length extension attack
      2. root cause: markle damgard constrction
   2. SHA3 use sponge contruction therefore, not vulnerable to that type of attack.

   
