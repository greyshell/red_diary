# Server side request forgery

## The Bug

1. Server side request forgery occurs when an attacker can force an application / server to request data / resources that he can't access directly.
2. The attacker use the application as proxy-server to interact with external systems / internal systems / same system.
3. If the application is vulnerable to XML eXternal Entity (XXE) injection then it can be exploited to perform a SSRF attack.

## Detection

1. Try finding the follwing keyword / patters in the burp history or source code
   1. proxy, feed, url, ip
   2. any parameter that takes URL as `value`
2. Examples:
   1. Load profile picture functionality where the application requests the image and saves it in server file system rather than embedding the image via `img` tag.
   2. API specification import / WSDL
   3. File import
   4. Connecting to remote servers
   5. Webhook
   6. ping / checklive utility
   7. pdf generator(lib or online utility)
      1. The attacker can use img tag and instruct the lib to fetch the resource

## Impact

Read / leak sensitive data / resource from private hosts / network.

1. File read / inclusion - etc/passwd, \~/.ssh/rsa\_keys
2. Steal authN info like windows NTLM hashes via UNC path like \`\`\attacker\_domain\share\_name\` and let the server authenticate to the fake share.
3. Map the internal network by using response time (Blind SSRF)

Depend on the context, we can also do the followings

1. We can extend the SSRF impact and do protocol smuggling via injecting CRLF and space.
2. Target the users of the vulnerable application via HTML injection => when the app fetches the remote HTML
3. Perform DoS with but hiding attacke's IP. The victim application will get the proxy server ip.
4. Log forging: Add corrupt data(trigger XSS) consumed by monitoring system.

## Exploitation

1. Most SSRF vulnerabilities limit us to generate certain kind of request like HTTP GET.
2. However, we can make non HTTP calls based on but it depends on primary two factors
   1. How the server's user-agent generates the forged request.
   2. If the attacker has the `full control of the generated URL`.

> Q. What is the difference between the schema and protocol
>
> A. Each schema has a corrosponding protocol.
>
> * For example `http` schema corrosponds to hypertext transfer protocol
> * Different versions of the HTTP protocol like 1.1, 1.2 use the same URL schema - http

The exploitation is depends on

1. What data that proxy app / server can access and
2. Whether the SSRF request returns any resulting data to the attacker that he can't access directly with his privillege.
3. What user-agent the app uses to reference a resource / file. For example, `head`, `curl`, `wget` etc.

> Mainly we can use SSRF vulnerability to retrieve the data.
>
> * Sometimes, we can even bypass the authN to retrieve the data.

#### What we can do with SSRF bug

1. In cloud environment, get sensitive data from internal meta data services - provide information(i.e private creds) about the environment or the machines in key:value pair.
   1. For example AWS metadata service-v1 `169.254.169.254`.
2. Host enum: interface with the vulnerable server itself (loop back interface) and send requests `across network boundaries` based on the server’s access.
3. Service/Port Enum: Perform service enumeration by checking the common TCP ports.
4. Interacting with backend services, mostly effective on microservice architecture based flat network. Here, those services mostly rely upon the API gateway or reverse proxy to provide security controls before forwarding the traffic to the application.
   1. Exploitation requires knowledge on the private ip range or hostname used by the internal network.
   2. Mitigation: API gateway should enforce the security control(i.e authN and authZ `istio`) on `traffic between the two microservices`.

> **What is Blind SSRF**
>
> As an attacker, we don't have access to the request contain or get any response data / resource.
>
> This could happen because
>
> 1. when the server accepts the link / URL, then it verifies that the `request only exists with` GET or HEAD and
> 2. finally `does not result any direct response` to the attacker.
>
> In blind SSRF scenario, we can
>
> 1. leak user `agent header`
> 2. any `token` by requesting a server that we control.

3. If the `user-agent` supports `file` schema then we can reference / read any local files on the server.
   1. Hostname can be ommited with one forward slash => no hostname
   2. three forwars slashes => empty hostname
   3. Check for windows and linux based file path, i.e `file:///c:/windows/win.ini`
   4. Python `requests` lib does not support `file` schema.

> For state changing request like POST / PUT, authN is required in form of a session cookie / authN header.
>
> In traditional scenario, if we only have `control to the URL field` the we will be restricted to the default GET / HEAD request.

5. However, if we can control the entire URL schema and the target server supports / interprets `Gopher` payload as other `text` based protocol request (like smtp, ftp) then it is possible to bypass many restrictions.
   1. We can use Gopher URLs to create valid requests in several different protocols like HTTP
   2. We also can add new line(`%0a`) to inject header on the request thus creating a state changing request with authN session / header.
   3. `curl` supports `gopher` protocol, tftp smtp telnet.
   4. Exploitation depends how the server interprets the gopher payload as other protocol request

#### Mimicing HTTP GET request via Gopher

```bash
gopher://127.0.0.1:80/_GET%20/status%20HTTP/1.1%0a
```

**Notes**

1. In the request, HTTP verb start with underscore. It is a fix for first character missing issue.
2. Terminate the request with new line char - %0a.
3. Explicitly mention the port number.
4. While replicating the request with Burp repeater then double encode any alphanumeric chars(like percentage char)

#### Mimicing HTTP POST request via Gopher

```
TBD
```

**Inconsistency between URL parser and requester**

1. Not all libs are interpreting the url component in the same way.

![image-20231124174642197](.ssrf.assets/image-20231124174642197.png)

2. In the php example, parse\_url() interprets the `port` in one way, on the other hand, readfile() interprets the `port` in different way.

![image-20231124192332529](.ssrf.assets/image-20231124192332529.png)

#### Protocol Smuggling

Can we Smuggle text based protocol like smtp over http.

1. To control the `host` we inject CR(\x0d) and LF(\0a).

![image-20231124180002523](.ssrf.assets/image-20231124180002523.png)

* It is possible to generate the request and reach out to smtp server. But now a days, for security reasons smtp servers blocks/ cut the http connections when it receives any `/` (forward slash).

However we can still use `https` protocol to smuggle the smtp.

> What is encrypted in TLS handshake:
>
> SNI, or Server Name Indication. It is _an extension for the TLS protocol to indicate a `hostname` in the TLS handshake_.

By injecting a `space`(x20) then CRLF we can control the host.

![image-20231124182339735](.ssrf.assets/image-20231124182339735.png)

### Exploit via open redirection

1. Find an app that has open redirect vulnerablility
2. Via proxy app target that other app that had the open redirect issue.

## Mitigation

#### Scenario 1: Cloud Context

In cloud environments SSRF is often used to access and steal credentials and access tokens from metadata services.

1. AWS context: To leverage this protection migrate to IMDSv2 and disable old IMDSv1.
2. With IMDSv2, every request is now protected by session authentication.

#### Scenario 2: Application can send requests to only identified and trusted applications hosted in private network

> Here attacker's primary objective is to get the data from other private ips / same host those are not expected by the functionality / business

#### 1. Mitigate Open redirection

1. Disable the support of redirection(like 302) in user-agent.

> How does the SSRF - open redirection attack occur?
>
> 1. One vulnerable app must be present in the network
> 2. Redirection support is enabled in the user agent.

> #### Concept: URL parser vs URL requester
>
> 1. URL parser is used to extract all `components` from the url then use it to `validate` each components.
>    1. For example: if the port is 80 or
>    2. if the ip address is private etc.
> 2. If all validations are passed then the code `passes the control` to URL requester that actually initiates the GET request.

![image-20231124162233828](.ssrf.assets/image-20231124162233828.png)

#### 2. Mitigate protocol smuggling issue

1. Use regex and remove the `space` from the `user input`.
2. Use a safe lib where there is `no inconsistency` between the URL parser and URL requester.
   1. Make sure both `interprests` the url components in the same way and
   2. both does not have CRLF and space injection bug to smuggle other protocol.
3. Whitelist the protocol when business only requires http:// or https:// to avoid non http based server exploitation like ftp:// or gopher.
4. Make sure `user-agent` should not support `gopher` protocol to smuggle other protocol.

> **Concept `DNS Rebinding / Pinning`**
>
> **Impact:**
>
> 1. Bypass ip validation restriction
> 2. It can also disclose information to external DNS resolvers.
> 3. if the app handles the dns communication via SDK / third party lib, then the rouge resolver can send malicious payload to exploit known vulnerability in that SDK.
>
> **Exploitation:**
>
> 1. URL parser extract the domain component from the URL.
> 2. Next, the code will try to check if that IP address corrosponding to the domain is in the allowed list
>    1. At first dns resolution happens
>    2. Here, the attacker's objective is the app server should reach out to his rouge dns resolver to get the ip.
> 3. This time the rouge dns resolver sends a valid ip to bypass the code check.
>    1. However, it also send very low / zero ttl value so that app can't cache that and use during URL requester.
> 4. When the URL requester initiates the request, again it will try to resolve the ip. therefore it will again come back to the rouge resolver.
> 5. This second time, the rouge resolver provides an ip that he wants to reach.

#### 3. Mitigate DNS rebinding issue

1. If we are accepting as domain name and ip both combination then
   1. first we need to check if that domain is valid via an allow list of trusted domain.
   2. second, we need to resolve the domain to get an ip. For that, we need to tell the app to relay only on trusted `internal` dns resolver/ `hardcoded` host file entries.
      1. DONT resolve ip via external dns resolver.
      2. In case, we need to depend on the external resolver then dont accept small / zero TTL value.
   3. Only trust ip that was resolved during the first time dns resolution then check if that ip is in the allowed list
   4. Finally, craft the request based on that `IP` NOT the `domain name` provided by the user via url to avoid `TOC - TOFU` issue (time of check - time of use).

#### Defense-in-depth:

1. Don't `send back` raw response to the `client` to prevent HTML injection.

> In SSRF - HTML injection, the functionality allows a user / admin to store a image for another user from a site.

2. Use network segmentation and use `allow list` in `host` and `network based firewalls`.
3. Restrict the `size` of the response that parser needs to parse.
   1. Update parser lib to prevent exploiting parsing related issue
   2. Don't display parsing error to end user.
4. Other apps/services in the network
   1. should not expose any sensitive resources and
   2. any state changing operation using http request like POST / PUT without AuthN / session token.
5. Maintain Audit log for all outgoing request for that functionality and
   1. periodic monitor and
   2. generate alerts for the suspicious request.

#### Scenario 3: Application can send requests to ANY external IP address or domain name

> This case happens when a user can control a URL to an **External** resource and the application makes a request to this URL (e.g. in case of WebHooks)
>
> **Challenges:**
>
> 1. Allow lists cannot be used here because the list of IPs/domains is often unknown upfront and is dynamically changing.
> 2. We need to allow public dns resolver.

> **Here attacker's primary objective is to**
>
> 1. Exfiltrate the data from any `private` ips / `same` host
> 2. Attack another public server / app to lunch the attack by using the vulnerable app as proxy server

1. Only trust IP that was resolved during the first time dns resolution and craft the request based on that `IP` only.
   1. After first time resolution, drop the request if it detects the IP is private.
2. Network segmentation: `Block` the intranet traffic / request via
   1. Host(via iptables) and
   2. Network based firewall both.

```bash
# Enhanced iptables rules that block access with pattern User-Agent: GitHub-Hookshot
$ cat /etc/ufw/before.rules
...
-A ufw-before-input -m multiport -p tcp ! --dports 22,23,80,81,122,123,443,444,8080,8081,8443,8444 -m recent --tcp-flags PSH,ACK PSH,ACK --remove -m string --algo bm --string "User-Agent: GitHub-Hookshot" -j REJECT --reject-with tcp-reset
...
```

3. Prevent protocol smuggling
4. Avoid exposing webhook tokens in URL / proxy logs, by supporting POST method

## References

* [x] Web200
* [ ] Web300
* [x] https://cheatsheetseries.owasp.org/assets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet\_SSRF\_Bible.pdf
* [x] https://cheatsheetseries.owasp.org/assets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet\_Orange\_Tsai\_Talk.pdf
* [x] https://www.youtube.com/watch?v=voTHFdL9S2k
* [x] https://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html
* [x] https://cheatsheetseries.owasp.org/cheatsheets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html
* [x] INE
* [ ] Rana kahali videos
* [ ] https://portswigger.net/web-security/ssrf
* [ ] notsosecure - adv web hacking
* [ ] Pentesterlab
* [ ] Pentester academy
* [x] web applicaiton hacker's handbook
* [ ] Browser hacker's handbook
* [ ] Real world bug hunting
* [x] hacker's codex
* [x] tangled web application gude

## TODO

1. for web200, craft the gopher payload for POST
