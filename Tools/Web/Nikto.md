# Nikto

Nikto is a web server scanner that tests web servers for dangerous files/CGIs, outdated server software, and other problems. It performs generic and server type specific checks. It also captures and prints any cookies received.

## Example Usage

```bash
nikto -host http://victim.site/wp-content
```

############################################################
User Dictionary Method
############################################################
Curl
// user doesn't exist

# curl -s -o /dev/null -w "%{http_code}\n" <http://victim.site/author/usr>

Result: 404

// user exist with 301 http status

# curl -s -o /dev/null -w "%{http_code}\n" <http://victim.site/author/user>

Result: 301

User Enumeration with Bash "for" loop w/ User Dictionary

# for i in $(cat users.txt); \

  do curl -s -o /dev/null -w "%{http_code}:$i\n" \
  http://victim.site/author/$i; done

Results:
404:steph
404:joe
301:admin
404:pete
404:frank
301:user
############################################################
Brute Force Method

# for i in {1..5}; \

  do curl -L -s <http://victim.site/?author=$i> \
  | grep -iPo '(?<=<title>)(.*)(?=</title>)' \
  | cut -f1 -d" " |grep -v "Page"; done

Results:
user
admin
############################################################
Directory indexing/listing
// Browse in the URL wp-content
victim.site/wp-content/

// Browse in the URL wp-content the plugins
victim.site/wp-content/plugins/

// Browse in the URL wp-content the changelog.txt or readme.txt for version of plugins
victim.site/wp-content/plugins/all-in-one-wp-migration
victim.site/wp-content/plugins/all-in-one-wp-migration/readme.txt
victim.site/wp-content/plugins/all-in-one-wp-migration/changelog.txt
############################################################
Bruteforce Atatcks

victim.site/wp-login.php
victim.site/wp-admin/wp-admin.php
