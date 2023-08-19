# Password Hashing

## Storing password in clear text

The attacker knows the password directly if he compromises the database.

## Storing a unsalted hash(fast algo) of the password 

1. Same passwords generates same hash if we don't use salt. Therefore, just by looking at the two same hashes the attacker infers that those two users have the same password.


2. Not resistant to Rainbow table attack
   1. The attacker try all possible passwords(dictionary attack) or bruteforce the short length space and create a rainbow table and from reverse lookup he could find the password. Here, the attacker needs to know the underlying hashing algorithm.
   2. If the hashing algorithm is fast then he can generate the rainbow table fast.



## Storing salted hash(slow algo) of the password

####  How to use salt

1. Don't use salt with `strong fast hasing` algo like sha3. Just by knowing the salt, the attacker can still generates the rainbow table fast.

   1. Don't use salt with `sha1`, `sha2` just by `prepending` it. It will increase the possibility for `hash length extention attack` where the attacker can calculate a valid hash for the password without knowing the salt (just by guessing its length). However, it is not easily exploitable for the password hashing context. 

2. Salt should be `unique` per user. Thus, two passwords don't produce the same hash.

3. Salt is not a `secret` means we can store in clear text. But it should not be accessible in public.

   1. We can store it in the same database but preferable saparate table from password.

4. Salt should be as long as the output of the hash, minimum 32 byte.

   1. If salt is too short, an attacker can again build the rainbow table for every possible salt. 

5. Use salt with

   1.  `slow computation`, `memory heavy` hash function like argon2, scrypt.
   2.  Support for XOF / variable length digest length
   3.  Bonus: support for `personalization` string (domain saperation)
   
   
   
   

>  Q. Can we use `username` or UID as salt
>
>  1. No. Because it does not generated from `un-predictable` source. 
>  2. Salt should be generated from csrng(i.e os.urandom()) function.
>  3. Could be too short. Does not meet minimum 32 byte requirement.



6. Use salt along with `pepper` to add extra defence in depth. 



> Q. What is crypto papper
>
> 1. A **pepper** is a `secret` added (prepend / postpend) to the password during hashing.
> 2. This value should differs from a salt and that it is not stored alongside a password hash, but rather the pepper is kept separate in some other medium, such as a `Hardware Security Module`.
> 3. NIST receommended size minimum 16 byte.
> 4. Should be generated from csrng(i.e os.urandom()) function.
> 5. It should be unique per application



#### What hashing properties we need to select a hashing algorithm for storing password

1. Support `Avalanche Effect` means a small changes in plain text results significantly change in cipher text.
2. Pre-image resistance, 2nd pre-image resistance and collision resistance.
3. Support `slow computation`, usage of multiple iteration, `memory heavy operation` to deter the offline rainbow table generation.
4. Support `salt` as a saparate input parmeter to the function.



> Q. Is there any performance impact if we use slow hashing functions.
>
> A. Yes. However, this intentional slow down can have an impact on the performance of an application, especially during the authentication process when users are logging in and their passwords need to be hashed and compared against stored hashes. 
>
> - To mitigate the performance impact, many applications use techniques such as parallelism, multi-threading, or specialized hardware to help mitigate the slowdown caused by slow hashing algorithms. 
>
> - Additionally, using appropriate work factor parameters when configuring the hashing algorithm can allow you to strike a balance between security and performance.



Following all key derivation functions are resistant to rainbow table attacks

1. PBKDF2 - (Not Recommended anymore)

   1. It is **not resistant** to 
      1. GPU attacks (parallel password cracking using video cards) and to 
      2. ASIC attacks (specialized password cracking hardware).

2. Bcrypt

   1. **Less resistant** to ASIC and GPU attacks. 
   2. It provides configurable iterations count, but uses constant memory, so it is easier to build hardware-accelerated password crackers.

3. Scrypt - (Recommended)

   1. It is memory-intensive, designed to prevent **GPU**, **ASIC** and **FPGA** based attacks (highly efficient password cracking hardware)

   2. XOF supported

   3. Function Arguments are 

      ```
      hash_key = Scrypt(password, salt, N, r, p, derived-key-len)
      
      config parameters are:
      1. password => the input password (8-10 chars minimal length is recommended)
      2. salt => securely-generated random bytes (64 bits minimum, 128 bits recommended)
      3. N => iterations count (affects memory and CPU usage), e.g. 16384 or 2048
      4. r => block size (affects memory and CPU usage), e.g. 8
      5. p => parallelism factor (threads to run in parallel, affects the memory, CPU usage), e.g. 1
      6. derived-key-length => how many bytes to generate as output, e.g. 32 bytes (256 bits)
      ```

4. Argon2 - (Recommended)

   1.  Strong resistant to GPU, ASIC and FPGA attacks.
   2. Argon2 config parameters are very similar to Scrypt.
   3. API - `argon2_cffi` lib also provides function that supports inbuild random salt generation.
   4. The Argon2 function has several variants:
      1. Argon2d – provides strong GPU resistance, but has potential side-channel attacks (possible in very special situations).
      2. Argon2i – provides less GPU resistance, but has no side-channel attacks.
      3. Argon2id – recommended (combines the Argon2d and Argon2i).



## Alternate Algorithm

Select a XOF based algorithm that supports the following

1. `variable length` digest output
2. `salt` parameter
3. `personalization` parameter

All those above parameters could be unique for every user. 

Therefore without having the source code access, it will be more challenging for the attacker to guess those values and build the rainbow table.



## References

1. https://crackstation.net/hashing-security.htm



## TBD

- rainbow table vs lookup table
- race condition and XOR based comparision
- when to use Blake, difference between 2b and 2s
- 