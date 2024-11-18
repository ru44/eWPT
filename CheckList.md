# comprehensive checklist to help you prepare for the eWPTX exam

**Disclaimer:** Always refer to the official syllabus and study materials for complete preparation.

## Checklist of Topics to Pass the eWPTXv2 Exam

### Tools

- [ ] **Burp Suite**: Proficiency in using Burp Suite for web application testing.
- [ ] **OWASP ZAP**: Understanding and using OWASP ZAP for web application testing.
- [ ] **SQLMap**: Proficiency in using SQLMap for SQL injection testing.
- [ ] **Nmap**: Understanding and using Nmap for network scanning.
- [ ] **Metasploit**: Proficiency in using Metasploit for exploitation.
- [ ] **Hydra**: Understanding and using Hydra for password cracking.
- [ ] **DirBuster**: Proficiency in using DirBuster for directory brute-forcing.
- [ ] **Nikto**: Understanding and using Nikto for web server scanning.
- [ ] **Wfuzz**: Proficiency in using Wfuzz for web application fuzzing.
- [ ] **Gobuster**: Understanding and using Gobuster for directory and file brute-forcing.
- [ ] **Sublist3r**: Proficiency in using Sublist3r for subdomain enumeration.
- [ ] **Amass**: Understanding and using Amass for subdomain discovery.
- [ ] **Cewl**: Proficiency in using Cewl for wordlist generation.
- [ ] **Hashcat**: Understanding and using Hashcat for password cracking.
- [ ] **John the Ripper**: Proficiency in using John the Ripper for password cracking.
- [ ] **Ysoserial**: Understanding and using Ysoserial for Java deserialization.
- [ ] **JWT Tool**: Understanding and using JWT Tool for JSON Web Token analysis.
- [ ] **OWASP Juice Shop**: Proficiency in using OWASP Juice Shop for practice.
- [ ] **OWASP WebGoat**: Understanding and using OWASP WebGoat for practice.
- [ ] **OWASP Mutillidae II**: Proficiency in using OWASP Mutillidae for practice.
- [ ] **DVWA**: Understanding and using DVWA (Damn Vulnerable Web Application) for practice.

### 1. Encoding and Filtering

- [ ] **Data Encoding Basics**: Understand different types of encoding (URL, HTML, Base36, Base64, Unicode).
- [ ] **Multiple (De|En)codings**: Learn how to handle multiple encodings.
- [ ] **Filtering Basics**: Gain proficiency in regular expressions and filtering mechanisms.
- [ ] **Web Application Firewall (WAF) Bypassing**: Techniques to detect and bypass WAFs.
- [ ] **Client-side Filters**: Study browser add-ons and native browser filters.

### 2. Evasion Basics

- [ ] **Base64 Encoding Evasion**: Techniques to evade detection using Base64 encoding.
- [ ] **URI Obfuscation**: Understand URL shortening, hostname obfuscation, and authority obfuscation.
- [ ] **JavaScript Obfuscation**: Techniques like non-alphanumeric encoding, minifying, and packing.
- [ ] **PHP Obfuscation**: Study type juggling, numerical and string data types, and variable variables.

### 3. Cross-Site Scripting (XSS)

- [ ] **Types of XSS**: Reflected, persistent, DOM, and universal XSS.
- [ ] **XSS Attacks**: Techniques like cookie grabbing, defacements, phishing, keylogging, and network attacks.
- [ ] **Exotic XSS Vectors**: Mutation-based XSS and advanced exploitation vectors.

### 4. XSS Filter Evasion and WAF Bypassing

- [ ] **Blacklisting Filters**: Bypass techniques for weak script tag banning and keyword-based filters.
- [ ] **Sanitization Bypassing**: Techniques to manipulate strings and escape quotes.
- [ ] **Browser Filters**: Understand how to inject code inside HTML tags and attributes, script tags, and event attributes.

### 5. Cross-Site Request Forgery (CSRF)

- [ ] **Attack Vectors**: Force browsing with GET and POST requests.
- [ ] **Exploiting Weak Anti-CSRF Measures**: Techniques to bypass post-only requests, multi-step transactions, and predictable tokens.
- [ ] **Advanced Exploitation**: Combining CSRF with XSS to bypass header checks and tokens.

### 6. HTML5 Attacks

- [ ] **HTML5 Features**: Analyze semantics, offline storage, device access, performance, integration, and connectivity.
- [ ] **Exploitation Techniques**: CORS attacks, storage attack scenarios, web messaging, web sockets, and web workers.
- [ ] **UI Redressing**: Techniques like clickjacking, likejacking, strokejacking, and drag-and-drop attacks.

### 7. SQL Injections (SQLi)

- [ ] **Techniques Classification**: Inband, out-of-band, and inference attacks.
- [ ] **Gathering Information**: Identify DBMS, enumerate DBMS content, and advanced exploitation.
- [ ] **Out-of-Band Exploitation**: Techniques using HTTP and DNS channels.
- [ ] **Second-Order SQL Injection**: Understand first-order and second-order examples.

### 8. SQLi Filter Evasion and WAF Bypassing

- [ ] **DBMS Gadgets**: Comments, functions, operators, intermediary characters, constants, and variables.
- [ ] **Bypassing Filters**: Case changing, using intermediary characters, alternative techniques, encoding, and replaced keywords.
- [ ] **Functions Filters**: Building strings and brute-forcing substrings.

### 9. XML Attacks

- [ ] **XML Basics**: Understand XML document structures and entities.
- [ ] **XML Injection**: Techniques for testing and exploiting XML injection.
- [ ] **XXE and XEE**: XML External Entity attacks and their exploitation.
- [ ] **XPath Injection**: Blind exploitation and out-of-band exploitation techniques.

### 10. Attacking Serialization

- [ ] **Serialization in Java, PHP, and .NET**: Understand serialization mechanisms and exploit untrusted deserialization.
- [ ] **Tools and Techniques**: Use ysoserial for Java deserialization and understand .NET serialization.

### 11. Server-Side Attacks

- [ ] **SSRF**: Server-Side Request Forgery attacks and their exploitation.
- [ ] **SSI and ESI**: Server-Side Include and Edge Side Include attacks.
- [ ] **Template Injection**: Exploiting server-side template injection.
- [ ] **XSLT Attacks**: Exploiting XSLT engines for file read, SSRF, and other attacks.

### 12. Attacking Crypto

- [ ] **Padding Oracle Attack**: Understand and exploit padding oracle vulnerabilities.
- [ ] **Hash Length Extension Attack**: Exploit hash length extension vulnerabilities.
- [ ] **Leveraging machineKey**: Exploit .NET machineKey for RCE.
- [ ] **HMAC in Node.js**: Subverting HMAC implementations in Node.js.

### 13. Attacking Authentication & SSO

- [ ] **JWT Attacks**: JSON Web Token vulnerabilities and exploitation.
- [ ] **OAuth Attacks**: Common OAuth attacks and scenarios.
- [ ] **SAML Attacks**: Security Assertion Markup Language vulnerabilities.
- [ ] **2FA Bypass**: Techniques to bypass two-factor authentication.

### 14. Pentesting APIs & Cloud Applications

- [ ] **API Testing**: Techniques for testing and attacking APIs.
- [ ] **Cloud Applications**: Attacks on microservices, serverless applications, and cloud storage.
- [ ] **GraphQL APIs**: Understand and exploit GraphQL vulnerabilities.

### 15. Attacking LDAP-based Implementations

- [ ] **LDAP Basics**: Structure and syntax of LDAP.
- [ ] **LDAP Injection**: Techniques for exploiting LDAP injection vulnerabilities.
- [ ] **LDAP Manipulation/Poisoning**: Exploiting LDAP implementations.

### 16. File-based Attacks

- [ ] **File Upload Vulnerabilities**: Bypassing file type restrictions, content-type validation
- [ ] **File Inclusion**: Local and Remote File Inclusion (LFI/RFI)
- [ ] **Path Traversal**: Directory traversal techniques and bypasses

### 17. Session Management

- [ ] **Session Fixation**: Understanding and exploiting session handling
- [ ] **Session Hijacking**: Techniques for intercepting and stealing sessions
- [ ] **Cookie Security**: Secure flag, HttpOnly flag, SameSite attribute

### 18. Command Injection

- [ ] **OS Command Injection**: Direct and indirect command injection
- [ ] **Filter Bypass Techniques**: Space bypass, concatenation techniques
- [ ] **Blind Command Injection**: Time-based and out-of-band exploitation

### 19. Business Logic Flaws

- [ ] **Race Conditions**: Identifying and exploiting timing issues
- [ ] **Parameter Manipulation**: Testing for logic flaws in parameters
- [ ] **Access Control**: Horizontal and vertical privilege escalation
