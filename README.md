# eWPT - Web Application Penetration Testing

## Table of Contents

- [Introduction](#introduction)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
  - [Reflected Cross-Site Scripting (XSS)](#reflected-cross-site-scripting-xss)
  - [Exploiting Reflected XSS](#exploiting-reflected-xss)
  - [Prevention Strategies](#prevention-strategies)
- [SQL Injection](#sql-injection)
  - [Boolean Blind SQL Injection](#boolean-blind-sql-injection)
  - [Error-Based SQL Injection](#error-based-sql-injection)
  - [Time-Based SQL Injection](#time-based-sql-injection)
- [Injection Attacks](#injection-attacks)
- [Other Exploits](#other-exploits)
- [Miscellaneous](#miscellaneous)
- [Enumeration](#enumeration)
- [Low/Informational Vulnerabilities](#lowinformational-vulnerabilities)
- [Report Template](#report-template)

## Introduction

Hi I'm RuM and I'm currently studying for the eWPT exam. I write these notes to help me understand the concepts better and to help others who are studying for the exam. I hope you find these notes helpful and if you have any suggestions or you want to add more stuff please make a PR, Most resources are from the [Sergio Medeiros](grumpz.net) please go check out his website for more information.

## Cross-Site Scripting (XSS)

*Cross-Site Scripting (XSS)* is a web vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. This occurs when an application includes untrusted data in its output without proper validation or escaping, allowing attackers to execute scripts in the context of other users' browsers.
and it can be classified into three types:

1. Reflected XSS
2. Stored/Persistent XSS
3. DOM-based XSS

### Reflected Cross-Site Scripting (XSS)

*Reflected XSS* is a web vulnerability where an attacker injects malicious scripts into a website that are immediately reflected back to the user without being stored on the server. This happens when an application dynamically includes untrusted user input in its response without proper sanitization or encoding.

#### How it Happens

1. User Input: A vulnerable website accepts user input (e.g., via a query parameter).
2. Response Reflection: The input is included in the HTML response without escaping.
3. Malicious Script Execution: An attacker crafts a malicious URL containing a script, and the victim unknowingly visits the URL, leading to script execution.

#### Vulnerable Code Example

```php
<?php
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    echo "Search results for: " . $search; // User input is reflected without sanitization
}
?>
```

#### Exploiting Reflected XSS

1. Exploiting Reflected XSS

```html
http://localhost:8080/eWPTXv2/reflectedXSS.php?search=<script>alert(1)</script>
```

1. Execution:

```html
Search results for: <script>alert(1)</script>
```

1. Impact: The script is executed in the context of the vulnerable website, allowing an attacker to steal cookies, redirect users to malicious sites, or deface the website.
The attacker can steal cookies, session tokens, or perform unauthorized actions.

#### Prevention Strategies

1. Escape Output :Use functions to escape HTML special characters:
   - PHP: `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`
   - Java: `StringEscapeUtils.escapeHtml4(input)`
   - Python: `cgi.escape(input)`
2. Use Content Security Policy (CSP) : Implement a Content Security Policy to restrict the sources of content that can be loaded on a page.
   - Example: `Content-Security-Policy: default-src 'self'`
3. Use HTTPOnly Cookies
4. Implement Input Validation : Validate and sanitize user input to ensure it adheres to expected formats and values.
   - PHP: `$search = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_STRING);`
5. Avoid inline JavaScript : Avoid inline JavaScript and use external scripts instead.
   - Bad: `<script>alert('XSS')</script>`

## Cross-Site Request Forgery (CSRF)

- Cross-Site Request Forgery (CSRF)
- Anti-CSRF Token Bypass using SQLmap

## SQL Injection

- SQL Injection
  - Boolean Blind SQL Injection
  - Time-Based SQL Injection
  - Error-Based SQL Injection
  - Time-Based SQL Injection (SQLi)
- Second Order SQL Injection

## Injection Attacks

- Command Injection
- XML External Entity (XXE)
- PHP Object Injection
- Java Deserialization
- Server Side Template Injection (SSTI)
- Server Side Request Forgery (SSRF)
- Out-of-Band (OOB) XML eXternal Entity Injection
- Host Header Injection

## Other Exploits

- File Upload Exploitation
- Session Hijacking

## Miscellaneous

- De-Obfuscate JavaScript Code
- PHP Coding Resources

## Enumeration

### Subdomain Brute Forcing

- [Bruteforcing Subdomains with Wfuzz](https://infinitelogins.com/2020/09/02/bruteforcing-subdomains-wfuzz/)
- [Subdomain Enumeration Guide](https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/dns-bruteforcing)
- [Subdomains Enumeration Cheatsheet](https://pentester.land/blog/subdomains-enumeration-cheatsheet/)
- [Google Dorking for Subdomain Enumeration](https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/#google-dorking)

### Directory Busting

- [Bug Bounty Recon: Content Discovery](https://medium.com/@nynan/bug-bounty-recon-content-discovery-efficiency-pays-2ec2462532b1)
- [Recon and Content Discovery](https://www.hackerone.com/ethical-hacker/how-recon-and-content-discovery)
- [YouTube: Directory Busting](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [Directory Bruteforcing Web Server](https://www.hackingarticles.in/5-ways-directory-bruteforcing-web-server/)
- [Total OSCP Guide: Web Scanning](https://sushant747.gitbooks.io/total-oscp-guide/content/web-scanning.html)

## Low/Informational Vulnerabilities

- [Clickjacking](https://www.imperva.com/learn/application-security/clickjacking/)
- [Session Fixation Attack](https://www.geeksforgeeks.org/session-fixation-attack/)
- [Missing Cookie Attributes (use Nikto!)](https://cirt.net/Nikto2)
- [No Rate Limiting?](https://gaya3-r.medium.com/no-rate-limiting-on-form-registration-login-email-triggering-sms-triggering-5961b64a91cb)

## Report Template

- [GitHub: TCM Security Sample Pentest Report](https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report)

## Master the Art of The Following Vulnerabilities

### Cross Scripting Resources

#### Reflected XSS

- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [BrightSec: Cross-Site Scripting (XSS)](https://brightsec.com/blog/cross-site-scripting-xss/)
- [YouTube: Reflected XSS](https://www.youtube.com/watch?v=k4lUX55uNM0)
- [Public Firing Range: Reflected XSS Labs](https://public-firing-range.appspot.com/reflected/index.html)

#### Stored/Persistent XSS

- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [The Ultimate Guide to Stored XSS Attacks](https://www.thesslstore.com/blog/the-ultimate-guide-to-stored-xss-attacks/)
- [Complete Cross-Site Scripting Walkthrough](https://www.exploit-db.com/docs/english/18895-complete-cross-site-scripting-walkthrough.pdf)
- [A Pentester's Guide to Cross-Site Scripting (XSS)](https://www.cobalt.io/blog/a-pentesters-guide-to-cross-site-scripting-xss)
- [PortSwigger: Reflected XSS Lab](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
- [PortSwigger: Stored XSS Lab](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

### SQL Injection Resources

Remember.. SQLmap is your best friend when exploiting these vulnerabilities. The -r switch goes a long way! ;-)

- [SQLmap](https://github.com/sqlmapproject/sqlmap)
- [SQLmap Cheatsheet](https://dl.packetstormsecurity.net/papers/cheatsheets/sqlmap-cheatsheet-1.0-SDB.pdf)
- [SQL Injection](https://portswigger.net/web-security/sql-injection)
- [Using SQLmap on a SOAP Request](https://hippidikki.wordpress.com/2018/07/12/using-sqlmap-on-a-soap-request/)

#### Boolean Blind SQL Injection

- [Beginner Guide to SQL Injection](https://www.hackingarticles.in/beginner-guide-sql-injection-boolean-based-part-2/)
- [Boolean Exploitation Technique](https://www.hackingloops.com/boolean-exploitation-technique-to/)
- [YouTube: Boolean Blind SQL Injection](https://www.youtube.com/watch?v=MfDo_ssS4PY)
- [Exploitation Blind Boolean-Based SQL Injection](https://null-byte.wonderhowto.com/forum/explotation-blind-boolean-based-sql-injection-by-mohamed-ahmed-0179938/)
- [PortSwigger: Conditional Responses Lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PortSwigger: Conditional Errors Lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PortSwigger: Time Delays Lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)
- [PortSwigger: Time Delays Info Retrieval Lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)

#### Error-Based SQL Injection

- [Example of Error-Based SQL Injection](https://medium.com/@hninja049/example-of-a-error-based-sql-injection-dce72530271c)
- [Manual SQL Injection](https://gbhackers.com/manual-sql-injection/)
- [SQL Injection Exploitation](https://rstudio-pubs-static.s3.amazonaws.com/117265_97cc9bec3f4a4952b37369ade413e435.html)
- [SQL Injection Exploitation Error-Based](https://akimbocore.com/article/sql-injection-exploitation-error-based/)

#### Time-Based SQL Injection

- [Time-Based Blind SQL Injection](https://beaglesecurity.com/blog/vulnerability/time-based-blind-sql-injection.html)
- [YouTube: Time-Based SQL Injection](https://www.youtube.com/watch?v=xHzH00vyVHA)
- [Security Idiots: Time-Based Blind Injection](http://www.securityidiots.com/Web-Pentest/SQL-Injection/time-based-blind-injection.html)

### File Upload Exploitation

- [File Upload](https://portswigger.net/web-security/file-upload)
- [Exploiting File Upload Vulnerabilities](https://www.prplbx.com/resources/blog/exploiting-file-upload-vulnerabilities/)
- [YouTube: File Upload Exploitation](https://www.youtube.com/watch?v=rPdn88pO7x0)
- [YouTube: File Upload Exploitation](https://www.youtube.com/watch?v=b6R_DRT5CqQ)
- [PortSwigger: Remote Code Execution via Web Shell Upload Lab](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
- [PortSwigger: Web Shell Upload via Content-Type Restriction Bypass Lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

### Session Hijacking

- [The Ultimate Guide to Session Hijacking](https://www.thesslstore.com/blog/the-ultimate-guide-to-session-hijacking-aka-cookie-hijacking/)
- [YouTube: Session Hijacking](https://www.youtube.com/watch?v=z6nUbsY5B-w)
- [YouTube: Session Hijacking](https://www.youtube.com/watch?v=T1QEs3mdJoc)
- [Session Hijacking Cheat Sheet](https://resources.infosecinstitute.com/topic/session-hijacking-cheat-sheet/)

### PHP Object Injection

PHP Object Injection is a type of security vulnerability where an attacker can manipulate and exploit an application's deserialization mechanism to execute unintended actions. This occurs when user input is passed to ```unserialize()``` without proper validation.

#### How it Happens

1. Untrusted Input to ```unserialize()```: User input is directly passed to the ```unserialize()``` function.
2. Malicious Serialized Object: An attacker crafts a malicious serialized object to exploit the application.
3. Triggering a Magic Method: PHP objects often have magic methods like ```__wakeup()``` ```__destruct()``` ```__toString()```  hat execute when an object is deserialized or destroyed. If these methods contain exploitable functionality, they can be abused.

- [Arbitrary Object Injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
- [Modifying Serialized Objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
- [PayloadsAllTheThings - PHP Object Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md#object-injection)
- [YouTube: PHP Object Injection](https://www.youtube.com/watch?v=KuqeNLTphR0)
- [YouTube: PHP Object Injection](https://www.youtube.com/watch?v=HaW15aMzBUM)

### Java Deserialization

- [Exploiting Java Deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
- [Exploiting Blind Java Deserialization](https://www.n00py.io/2017/11/exploiting-blind-java-deserialization-with-burp-and-ysoserial/)
- [Tricking Java Serialization](https://securitycafe.ro/2017/11/03/tricking-java-serialization-for-a-treat/)
- [Testing and Exploiting Java Deserialization](https://blog.afine.com/testing-and-exploiting-java-deserialization-in-2021-e762f3e43ca2)

### Server Side Template Injection (SSTI)

- [Server Side Template Injection](https://redfoxsec.com/blog/server-side-template-injection/)
- [Server Side Template Injection in Tornado](https://ajinabraham.com/blog/server-side-template-injection-in-tornado)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PortSwigger: Basic Code Context](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)
- [PortSwigger: Basic](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)
- [PortSwigger: Using Documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

### Server Side Request Forgery (SSRF)

- [SSRF Guide](https://www.prplbx.com/resources/blog/ssrf-guide/)
- [SSRF Attacks](https://nira.com/server-side-request-forgery-ssrf-attacks/)
- [YouTube: SSRF](https://www.youtube.com/watch?v=eVI0Ny5cZ2c)
- [YouTube: SSRF](https://www.youtube.com/watch?v=Ku6CK3Aes8Y)
- [PortSwigger: Basic SSRF Against Localhost](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
- [PortSwigger: Basic SSRF Against Backend System](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)

### Second Order SQL Injection

- [Second Order SQL Injection Attack](https://offensive360.com/second-order-sql-injection-attack/)
- [The Wrath of Second Order SQL Injection](https://infosecwriteups.com/the-wrath-of-second-order-sql-injection-c9338a51c6d)
- [Second Order SQL Injection Attack](https://www.varutra.com/second-order-sql-injection-attack/)

Note: Please do not depend on SQLmap for each SQL injection that you find, not all of them can be exploited using SQLmap, and you may need to exploit them manually. In this case, be sure that you understand why you are using special characters like ' or # when testing manually. ;)

### Anti-CSRF Token Bypass using SQLmap

- [Bypassing Web Application Protections](https://forum.hackthebox.com/t/bypassing-web-application-protections-sqlmap-essentials/267869)
- [Bypassing Web Protections](https://neutronsec.com/tools/sqlmap/bypassing_web_protections/)

### Out-of-Band (OOB) XML eXternal Entity Injection

- [Blind XXE Attacks](https://shreyapohekar.com/blogs/blind-xxe-attacks-out-of-band-interaction-techniques-oast-to-exfilterate-data/)
- [PortSwigger: XXE with Out-of-Band Interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
- [PortSwigger: XXE with Out-of-Band Interaction Using Parameter Entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
- [PortSwigger: XXE with Out-of-Band Exfiltration](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)

### Host Header Injection

- [Exploiting Host Header Injection](https://portswigger.net/web-security/host-header/exploiting)
- [Host Header Injection](https://www.secuneus.com/host-header-injection/)
- [AllAboutBugBounty - Host Header Injection](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Host%20Header%20Injection.md)

### De-Obfuscate JavaScript Code

- [De-Obfuscate JavaScript Code](https://stackoverflow.com/questions/12921713/de-obfuscate-javascript-code-to-make-it-readable-again)
- [JS Beautifier](http://jsbeautifier.org/)

### PHP Coding Resources

- [PHP Looping](https://www.w3schools.com/php/php_looping_for.asp)
- [PHP OpenSSL Encrypt](https://www.php.net/manual/en/function.openssl-encrypt.php)
- [PHP If Else](https://www.w3schools.com/php/php_if_else.asp)

### Time-Based SQL Injection (SQLi)

## Conclusion

Explore thoroughly by searching for hidden directories, subdomains, and endpoints that could be leveraged to create attack chains. Finding one vulnerability is just the beginning; look for ways to link it with other vulnerabilities to form a more powerful attack chain.
