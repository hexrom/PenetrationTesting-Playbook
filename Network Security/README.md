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
**Basic**  
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
