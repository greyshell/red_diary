# Code Review Methodology

1. App overview & risk assessment
   1. What the functionality
   2. who is the user, how they use 
   3. domain and protocol used to run the code
2. How the request is processed / how the function handles the input arguments
   1. data validation related issue
      1. Injection issues (XSS, header, sql, command, XML, redirection) 
      2. SSRF
      3. insecure deserialization
      4. Path traversal, file upload and download
      5. Insecure redirection
3. How authN is handled by the code / each function level
   1. How authN is handled by each endpoint
   2. credential storage and enforced policy(i.e strong password)
   3. AuthN related issues
      1. Is basic authN
      2. bruteforce attack
      3. Race condition 
      4. sensitive page access by force browsing
      5. user enumeration
4. How does it handle session
   1. cookie attributes and security
   2. cookie tampering
   3. session timeout and persistance
   4. session replay
   5. JWT token
   6. CSRF and login csrf
5. What are the different roles 
   1. How roles are validated 
   2. IDOR issue
   3. JWT validation
6. Information Leackage
   1. hardcoded credentials / PII / privacy data
   2. How does it handles the error / provide error message to end user
   3. privacy related issues
7. Audit and Logging
   1. are all state changing operations have the audit log
   2. what information are logged, any privacy issue
   3. useage of proper logger function instead of system.out.println
   4. log forging or log manipulation 
8. Insecure usage of crypto
   1. outdated or bad protocol/ construct used
   2. lack of ctypto control
   3. insecure token generation
9. Insecure Configuration
   1. What are the response headers
      1. http methods
      2. http headers
   2. hardcoded creds
   3. insecure protocol / CSP
10. Bad practice
    1. string compare
    2. left over debug code
    3. infinite loop
    4. empty catch block
    5. overly broad catch
    6. throw inside finally block
