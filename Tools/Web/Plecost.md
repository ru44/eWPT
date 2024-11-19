# Plecost

Plecost is a WordPress fingerprinting tool, it can search and retrieve information about the plugins and themes installed in WordPress sites. It can be used to scan a list of websites and discover the plugins and themes used in each one of them. It also as an API that can be used to retrieve information about plugins and themes from WordPress sites.

## Command for identifying installed plugins, versions and related vulnerabilities

```bash
plecost -i /usr/share/plecost/wp_plugin_list.txt http://victim.site
```
