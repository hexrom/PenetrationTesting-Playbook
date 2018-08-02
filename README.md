# eCPPT-Notes
Notes and things from the eLearnSecurity eCPPT course

### Table of Contents
1.Network Security  
2.PowerShell for Pentesters  
3.Linux Exploitation  
4.Web App Security  
5.WiFi Security  
6.Ruby & Metasploit  
7.System Security  

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

```
$ Nslookup -query=any domain.com
or
>nslookup
>server <target>
>set q=NS
>set q=MX
>domain.com
>ns1.domain.com
```
$ Nmap -sS -sU -p53 -n target/24  
$ Dig domain.com A - Query "A" Record of a domain  
$ Dig +nocmd domain.com AXFR +noall +answer @serverIP - Zone Transfer  
$ Dig @serverIP domain.com -t AXFR +nocookie - Zone Transfer  
