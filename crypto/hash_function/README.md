# Hash Function

1. In the context of practical crypto, hash functions cannot be relied upon alone
Let's take the example of a secure file download and hash verification feature:
    1. An attacker could perform a Man-in-the-Middle (MITM) attack or compromise the website, allowing them to replace both the file and its associated hash.
    2. To ensure the integrity and authenticity of the downloaded file, it is necessary to rely on `trusted mechanisms` such as Transport Layer Security (TLS) and hosting sites that cannot be compromised.
    3. Message Authentication Code (MAC) addresses this issue by incorporating secrets, providing a solution that ensures both integrity and authenticity. The same we can achieve by signing the hash with private key(digital signature).

2. Checksum vs Hash functions
- In general, `checksum` term is used for `non-crypto` hash functions. It is primary used for error checking. 

3. Why `base64` encoding is used as a standard output of all hash functions
The larger the base, the less space it takes to display a binary string.

4. Can we use crypto hash functions as `Random Oracles` or random string generation
Although the hash functions are designed in such a way that their digests are `unpredictable` and random but still we can't replace `Random Oracles` with real hash functions.

5. Why does dev team afraid of upgrading the hash function
- Support backward compatibility

6. Verify the digest of a downloaded file
```bash
openssl dgst -sha256 downloaded_file
```

## Hash function properties
1. `Pre-image resistance` 
No one should be able to `reverse` the hash function in order to `recover` the `input` from the output.

- This is also called `one-way` property.
- It is always possible to find the plan text from a digest if that pain text is small (brute force the space) or predictable (use dictionary) to fill up a rainbow table and reverse lookup. However, here we are assuming, if the digest is generated from a large / un-predictable(i.e not from dictionary words) text then just by knowing the hash, we can't `recover` the plain text.
    
2. `Second pre-image resistance`
Knowing the `plain text` and the `hash` both, we can't find another input that produces the `same` hash.

This property is merely saying that it is `extreamly hard` to find another input.
Here, `extreamly hard` means we assume that it is practically impossible but not theoretically possible. Because end of the day, all hash functions are compressing the input.

> Commitment scheme: Hiding with Binding
> 1. Pre-image resistance: Hinding the input inside output / digest.
> 2. 2. Second pre-image resistance: Binding only a single input to the digest.

3. `Collision resistsnce`
No one should be able to `produce two different input` that generates the same hash output.

The primary difference with `Second pre-image resistance` property:
    - Here an attacker is `free to choose` any two different inputs but in `Second pre-image resistance`, one input and it's hash both are fixed, knowing those two information, the attacker needs to find another input that generates the same hash.

Interesting thing to note: These last two propertes are merely saying that it should be`extreamly hard` to find another input / two inputs.
`Extreamly hard` means => it is practically impossible but not theoretically possible. Because end of the day, all hash functions are compressing the input.

### Can we truncate the hash as per our choice
lets assume,
1. We generate multiple digests using random inputs.
2. The size of our digests is set to N bits, which means there are a total of 2^N possibilities.
3. According to the "birthday bound" concept, if there are only 23 people in a room, there is a 50% chance that two people share the same birthday.
4. Similarly, following the "birthday bound," there is a 50% probability of encountering a collision after generating 2^(N/2) strings.

In simpler terms, if we set the digest size to a minimum of 256 bits or 32 bytes, it would require someone to perform a minimum of 2^128 operations to find a collision with a 50% probability.

Performing 2^128 operations or pre-computing 2^128 strings would take an incredibly long time and is virtually impossible given the capabilities of today's standard computers. Due to this fundamental reason, all real world crypto algorithms aim for 128 bit security.

When we don't require a specific hash property to satisfy, we have the option to shorten the hash output or reduce its size.
Digest size: minimum requirement
    1. Pre-image resistance: 128 bit
    2. Second Pre-image resistance: 128 bit
    3. Collision resistance: 256 bit

For example: onion address => organization creates `base32` representation of hash contains the same name of the website. This type of website address is called `onion` /  `vanity ` address. 
    1. They generate lots of public keys until one ended up hashing to a cool base32 representation.
    2. They can also truncate the hash to achieve cool base32 representation because this hash does not need to meet collision resistance property.
