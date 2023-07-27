# Hash Function

## Hash function and Integrity
- Context: secure file download feature
- In the context of practical crypto, hash functions cannot be relied upon alone.
- The intended objective of that feature: 
  - no attacker should be able to fool you by giving you a different file that means second pre-image resistance property must be satisfied. 
  - The digest is closely tied to the file you’re downloading.

- However, an attacker could perform a Man-in-the-Middle (MITM) attack or compromise the website, allowing them to replace both the file and its associated hash.
- To ensure the integrity and authenticity of the downloaded file, we need to rely on `trusted mechanisms` such as 
  - Transport Layer Security (TLS) and 
  - hosting sites that cannot be compromised.

- Message Authentication Code (MAC) addresses this issue by incorporating secrets, providing a solution that ensures both integrity and authenticity. The same we can achieve by signing the hash with private key(digital signature).

## Checksum
- Checksum term should be used for non crypto context.
- Checksums are primarily used for error detection in data transmission or storage. They are designed to quickly identify accidental errors or corruption in data.
- Checksum algorithms are often simpler and faster to compute.
- They don't follow the hash property. In some cases, different inputs may produce the same checksum, leading to a collision.
- Example, CRC32.

## Encoding and Hash Output
> The number of human-readable characters depends on the character set. ASCII consists of 128 characters however Unicode encompasses thousands of characters, making it more comprehensive than ASCII.
- The larger the base, the less space it takes to display a binary string. 
- Base64 is commonly used to represent binary data in a human-readable format by using a set of 64 characters (hence the name Base64).
- Base64 is not designed to extend the character set beyond the existing human-readable characters. Instead, it aims to encode binary data into a format that is safe for transmission over systems that may interpret binary data differently.
- Base64 encoding is commonly used as a output of hash functions.
- TBD - what are the other supported encodings 

## Hash functions as Random Oracles
- Although the hash functions are designed in such a way that their digests are `unpredictable` and random but still we can't replace `Random Oracles` with real hash functions.
- TBD

## Challenges to upgrade hash function
1. Support backward compatibility

## Verify the digest of a downloaded file
```bash
openssl dgst -sha256 downloaded_file
```

## Size of hash / digest
- The input of hash function can be of any size. It can even be empty. 
- The output is always of the same length and deterministic

## Usage of Hashing function
1. Commitment scheme: Hiding with Binding
    - Pre-image resistance: By making a commitment we are hinding the actual input inside output / digest. For example, I am forcasting Stock X will reach $50 next month.
    - Second pre-image resistance: Binding only a single input to the digest.
2. Subresource integrity check: when web pages import external JavaScript files / libraries. 

## Hash properties

### 1. Pre-image resistance
No one should be able to `reverse` the hash function in order to `recover` the `input` from the output.

- This is also called `one-way` / irreversible property.
- It is always possible to find the plan text from a digest if that pain text is small (brute force the space) or predictable (use dictionary) to fill up a rainbow table and reverse lookup. However, here we are assuming, if the digest is generated from a large / un-predictable(i.e not from dictionary words) text then just by knowing the hash, we can't `recover` the plain text.
  
### 2. Second pre-image resistance
Knowing the `plain text` and the `hash` both, we can't find another input that produces the `same` hash.

This property is merely saying that it is `extreamly hard` to find another input.
Here, `extreamly hard` means we assume that it is practically impossible but not theoretically possible. Because end of the day, all hash functions are compressing the input.

### 3. Collision resistsnce
No one should be able to `produce two different input` that generates the same hash output.

The primary difference with `Second pre-image resistance` property:

- Here an attacker is `free to choose` any two different inputs but in `Second pre-image resistance`, one input and it's hash both are fixed, knowing those two information, the attacker needs to find another input that generates the same hash.

> These last two propertes are merely saying that it should be`extreamly hard` to find another input / two inputs. `Extreamly hard` means => it is practically impossible but not theoretically possible. Because end of the day, all hash functions are compressing the input.

#### 4. Other properties
1. Deterministic: the same input message should always result in the same hash value.
2. Quick: it should be fast to compute the hash value for any given message.
3. Hard to analyze: a small change to the input message should totally change the output hash value.

## Can we truncate the hash as per our choice
Lets assume,
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



