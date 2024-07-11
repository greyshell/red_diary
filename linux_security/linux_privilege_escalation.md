# Linux Privilege Escalation

`/etc/passwd` => this file does not contain a password. If the user has a password then it has * that indicates the salted_hashed password is stored in `/etc/shadow` file.


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



