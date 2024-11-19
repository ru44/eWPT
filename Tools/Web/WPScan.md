# WPScan

WPScan is a black box WordPress vulnerability scanner.
you can update the tool by running the following command:

```bash
wpscan --update
```

## Non-intrusive scan

```bash
 wpscan --url <http://victim.site>
```

## User enumeration

```bash
wpscan --url http://victim.site --enumerate u
```

## enumerate most popular plugins

```bash
wpscan --url http://victim.site --enumerate u
```

## brute force

```bash
wpscan --url http://victim.site --wordlist /usr/share/wordlists/rockyou.txt --username admin
```
