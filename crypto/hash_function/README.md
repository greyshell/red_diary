# Hash Function

1. In general, `checksum` term is used for `non-crypto` hash functions.
2. Feature `file download and hash match `
    1. In order to provide `integrity` and `authenticity` both it relays on the trusted mechanism(i.e https, uncompromisable hosting site) that provides the digest. 
    2. In other words, hash or digest can't provide integrity by itself. `Message Authetication code` fixes this by introducing `secrets`.
3. The larger the base, the less space it takes to display a binary string. Due to this `base64` encoding is used as a standard output of the hash function.
4. Although the hash functions are designed in such a way that their digests are unpredictable and random but still we can't replace `Random Oracles` with real hash functions.
5. In real world cryptography, algorithm aims for 128 bit security. Means to break the algorithm, someone has to perform 2^128 operations.
6. Birthday bound: If we have 23 people in the room, then there is 50% probability that two person share the same birthday.
7. We can truncate hash output and reduce the size but it depends on that property we relie on. Minimum requirement for 
    1. Pre-image resistance: 128 bit
    2. Second Pre-image resistance: 128 bit
    3. Collision resistance: 256 bit
8. Hash functions `rarely use alone` in practical scenarios.
9. Commitment scheme: hiding with binding
    1. Hiding -> Pre-image resistance
    2. Binding -> Second pre-image resistance
10. Sometimes organization creates base32 representation of hash contains the same name of the website. This type of website address is called `onion` /  `vanity ` address. 
    1. They generates lots of public keys until one ended up hashing to a cool base32 representation.
    2. They can also truncate the hash to achieve cool base32 representation because this hash does not need to meet collision resistance property.
11. The strong reason from dev not to upgrade the hash function is the backword compatibility.
12. Verify the digest of a downloaded file
```bash
openssl dgst -sha256 downloaded_file
```

## Hash function properties
1. `Pre-image resistance` 
    1. No one should be able to `reverse` the hash function in order to `recover` the `input` from the output. 
    2. Knowing only the hash, I can't `recover` the input.
    3. `Caveat`: If you create digest that is `small` / `predictable` then backtrack to the `input` is possible from the output. Because the attacker can generates all strings with all possible combination of letters, generates all it's hashes and stores into a hash-table(key: hash, value: input_string)
2. `Second pre-image resistance`
    1. No one should be able `find another input` that will produce to the same output / hash.
    2. Knowing the `input and the hash both,` I can't find another input that produces the `same` hash.
    3. This property merely saying that it is `extreamly hard` to find another input.`Extreamly hard` means we assume that it is practically impossible to find another input but not theoretically impossible.

3. `Collision resistsnce`
    1. No one should be able to `produce two different input` that produce the same hash output.
    2. The difference with `Second pre-image resistance` property
        1. In this case, an attacker controls / `free to choose` any two inputs but in `Second pre-image resistance`, one input and its hash both are fixed.
        2. That's why size of the digest matters. `Minimum` output size `256` bit / 32 byte. How does this `256` bit came from: If we randomly generates strings from a space or 2^N possibilities then there is a 50% chance / probability to find a collision after `approximately`  2^(N/2) strings.
    3. Regarding onion address, they don't need to satisfy this property so they truncate the hash output. Therefore, always verify the context to check which hash properties are required.

