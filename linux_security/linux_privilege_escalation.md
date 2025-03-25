# Linux Privilege Escalation

{% @lucid/lucid-component url="https://lucid.app/lucidspark/31de42af-f972-4ec6-bdc9-aba55594e263/edit?invitationId=inv_928b39ac-5b68-42ab-b36d-7a4f73e283b6&viewport_loc=-1525,-867,3413,1627,0_0" %}



`/etc/passwd` => this file does not contain a password. If the user has a password then it has \* that indicates the salted\_hashed password is stored in `/etc/shadow` file.

```
Structure of an entry in `/etc/shadow` file

kali:$y$j9T$hW9K52EOJBFsViQ7HRz370$//6l5BWkvHl3PTkK6qgZhGFTLOFKR/zVCEwjlZIwAq0:19778:0:99999:7:::

0. $ is the marker
1. kali => username
2. y => indicates the hashing algorithm - `yescrypt`.
    - 1 for MD5, 5 for SHA-256, 6 for SHA-512.
3. j9T => cost parameter for the hashing algorithm that defines the conputational cost.
4. hW9K52EOJBFsViQ7HRz370 => salt used
5. //6l5BWkvHl3PTkK6qgZhGFTLOFKR/zVCEwjlZIwAq0 => hashed password.
6. Last Password Change: 19778 days since January 1, 1970
7. Minimum Password Age: 0 days
8. Maximum Password Age: 99999 days
9. Password Warning Period: 7 days
10. Password Inactivity Period: None specified
11. Account Expiration Date: None specified
12. Reserved Field: Not utilized
```

1. misconfigured file permissons
   1. world readable `/etc/shadow` file: The unshadow utility is used to combine /etc/passwd and /etc/shadow files into a single format that John the Ripper can understand. then crack using `john --show unshadowed.txt`.
   2. world writable `/etc/shadow` file: overwrite the encrypted password with new password.
   3. `/etc/passwd` is world writable: `/etc/passwd` takes precedence over `/etc/shadow` – Encrypted password can be added directly in `/etc/passwd`

## Reference

1. pentesteracademy linux privilege escalation bootcamp
