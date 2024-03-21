# Hash Length Extension Attack

## The Bug

This type of attack occurs when the application `prepends` a `secret` / `key` to the data and creates the digest(to support authenticity) by using `markle-damgard` construction. 

## Impact

Without knowing the backend secret, the attacker can calculate a `valid` hash thus bypassing `integrity` and `authenticity` of the message.

## How to exploit

>  merkle-damguard construction: Padding is depends on his the fact that hashes are calculated in blocks and the hash of one block is the state for next block.



The attacker only needs to guess the `length of the secret` to determine how many bytes of padding required.

- With limited information he can also brueforce the length to min - max space.

## Black box perspective

- Find a response that provides the hash.
  - In the request, what parameters are used by the backend to generate the hash
- Check which order those parameters are used.
- Guess the algorithm used - iterate through md5, sha1, sha256
- If you can't generate the same hash after the combination of those parameters then may be secret / is used.
- Check if the hash returns direct filename or hash
  - try to access /etc/passwd

## Practical Scenario

![image-20231103042923158](./.hash_length_extension_attack.assets/image-20231103042923158.png)

![image-20231103043344391](./.hash_length_extension_attack.assets/image-20231103043344391.png)

![image-20231103044427955](./.hash_length_extension_attack.assets/image-20231103044427955.png)

## Exploitation

1. Find the POST request that sends a hash to server
2. Find out what type of hash and wheather it is vulnerable to hash length attack or not.
3. Find out what parameters are used in hashing function by generating the hash validation error in response.

```
# simple test if the concatination is used in the backend
transactionid=95866a4654654654&email=dhruv.nss@mailninator.com&amount=248
=> transactionid=95866a4654654654&email=dhruv.nss@mailninator.com248&amount=
# if success then we are purchasing with 0 value
-> we can also put everything in transactionid but payment gets success with a garbage transaction id.
transactionid=95866a4654654654dhruv.nss@mailninator.com248&email=&amount=
```



1. Find out the order of those parameters used in the function.
   1. If n parms are used then nC1 combinations.
2. Verify if the md5(transactionid || email || amount) matches with the existing hash. 
   1. If not then there could a possibility that a secret is pre-pended and used .
3. Identify the block size - for example md5 processes data in 512-bit (64-byte) blocks.



> 1. MD5 pad signature: 1 followed by the zeros
>
> 2. last byte is reserved for the length of the actual message



Tool used: https://github.com/iagox86/hash_extender

Objective: Try to purchase with amount 10 instead of 248.

```bash
data = (transaction_id || email || amount) =>  ("958661000887623dhruv.nss@mailninator.com248") 
./hash_extender --data "" 
								--secret-min 8 
								--secret-max 18 
								-append 10  => want to append "10" as amount so that it will complute as new block
															=> it is possible because in the HTTP POST request we send new top up value in 
															amount parameter. we concatinate old amount data with email value.
															i.e grey.shell@gmail.com248
															=> if the app does not allow the amount field to be empty then we need to use
															parameter pollution vulnerability and add extra "amount" parameter with "10"
								--signature <captured hash value>
								--format md5
								--out-data-format html --table
								
- capture the result into notepad.
- 1st it generates the message with padding and new value considering the secret length=8 then 9 and so on
- pad signature starts with %80(i.e 0x80 => ASCII representation is char 1) followed by %00%00..%00
- hash value will be same for all variations because we are adding padding based on the different secret length so messages length will vary.(padding lenght will decrease from top(secret-min=8) to bottom(secret-max=18))
- However, out of 11 different combinations of messages, 1 should be the TRUE combination that generates that hash.
- dont put the payload on transactionid param because it will make the successfull payment on a garbage transaction id. 
- fuzz the email parm in via intruder, impact would be - atleast you will not get any email
- amount=10
- hash=<new_hash>
- remove transaction id from the payload section because it is already availabe in the parm
- remove the amount=10 from the payload section because it is already availabe in the parm
- disable URL encoding
```

Clean up the payload - removing transaction id and amount=10

![image-20231103035223287](./.hash_length_extension_attack.assets/image-20231103035223287.png)



![image-20231103034521974](./.hash_length_extension_attack.assets/image-20231103034521974.png)

The 4th payload went through.

payload 0 => actual request, payload 1 => secret length 8, `payload 4` => secret length 11

![image-20231103035619540](./.hash_length_extension_attack.assets/image-20231103035619540.png)

4th payload -> request in browser and get the credit card with order id page for final stage of purchase.

![image-20231103043801028](./.hash_length_extension_attack.assets/image-20231103043801028.png)

Another example:

![image-20231103104425946](./.hash_length_extension_attack.assets/image-20231103104425946.png)

## Mitigation

1. Append the secret at the end of the message where message is a seriaized object
   1. have proper field demarkation char with the length of each field
   1. i.e h(transaction_id || 5 || email || 10 || amount || 3 || key || 8)
2. Use HMAC, KMAC if you prefer SHA3/ cSHAKE (both uses sponge construction)
3. Use tuple hash function.



