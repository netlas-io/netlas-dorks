# Netlas Featured Queries <!-- omit in toc -->

In this document, you will find dorks for the [Netlas.io](https://netlas.io/)  search engine. They are divided into several categories, and each dork includes a link to perform the search on Netlas. The [dork list](https://book.redteamguides.com/guides/tips-and-tricks) from RedTeamGuide was used as a basis and processed according to our syntax.

If you find any inaccuracies, please feel free to send pull requests or write Issues.

*Note*: In some cases, you will see two dorks. This is typically done to duplicate the request made using a tag. In Netlas, the use of tags is available starting with a Business subscription, so users of the Community, Community II, and Freelancer levels should pay close attention to the duplicate dorks.

---

## Contents <!-- omit in toc -->

- [General Searches](#general-searches)
- [IoT, Routers and Security](#iot-routers-and-security)
- [Security Applications](#security-applications)
- [Web cameras](#web-cameras)
- [Communication](#communication)
- [Remote Access](#remote-access)
- [VoIP](#voip)
- [Storages and Databases](#storages-and-databases)
- [Web Services](#web-services)
- [Developing and Monitoring](#developing-and-monitoring)
- [Other](#other)
- [2024 Interesting CVEs](#2024-interesting-cves)
- [2023 Interesting CVEs](#2023-interesting-cves)

---

## General Searches

- **AMQP** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=amqp%3A*&page=1&indices=) 
  ```text
  amqp:*
  ```
- **ASN**, IP WHOIS search &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/whois/ip/?q=asn.name%3ACERN&page=1) [[Alt&nbsp;&rarr;]](https://app.netlas.io/whois/ip/?q=asn.number%3A513&page=1&indices=)    
  ```text
  asn.name:"asnName"
  ```
  ```text
  asn.number:asnNumber
  ```
- **City** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=geo.city%3ALondon&page=1&indices=)     
  ```text
  geo.city:cityName
  ```
- **Country** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=geo.country%3AGB&page=1&indices=)     
  ```text
  geo.country:countryName
  ```
- **Directory Listings** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22%2Findex%20of%2F%22&page=1&indices=)    
  ```text
  http.title:"/index of/"
  ```
- **DNS**, DNS search &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/domains/?q=domain%3A*.netlas.io&page=1)    
  ```text
  domain:domainName
  ```
- **FTP** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Aftp&page=1&indices=)    
  ```text
  prot7:ftp
  ```
- **FTP banner** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=ftp.banner%3A%22ProFTPD%22&page=1&indices=)     
  ```text
  ftp.banner:"bannerText"
  ```
- **FTP without autorization** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=port%3A21%20AND%20ftp.banner%3A%22230%22&page=1&indices=)     
  ```text
  port:21 AND ftp.banner:"230"
  ```
- **IPSec** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(port%3A500%20OR%20port%3A4500%20OR%20port%3A1701)&page=1&indices=)    
  ```text
  port:500 OR port:4500 OR port:1701
  ```
- **Modbus** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=protocol%3Amodbus&page=1&indices=)    
  ```text
  protocol:modbus
  ```
- **Netbios** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=protocol%3Anetbios&page=1&indices=)    
  ```text
  protocol:netbios
  ```
- **Redis** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=protocol%3Aredis&page=1&indices=)    
  ```text
  protocol:redis
  ```
- **SMB** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Asmb&page=1&indices=)    
  ```text
  prot7:smb
  ```
- **SMTP** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Asmtp&page=1&indices=)    
  ```text
  prot7:smtp
  ```
- **SOCKS** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Asocks&page=1&indices=)    
  ```text
  prot7:socks
  ```
- **SSH** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=protocol%3Assh&page=1&indices=)    
  ```text
  protocol:ssh
  ```

---

## IoT, Routers and Security

- **All IoT devices** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.category%3A%22IoT%22&page=1&indices=)     
  ```text
  tag.category:"IoT"
  ```
- **Barracuda** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22BarracudaHTTP%22&page=1&indices=)     
  ```text
  http.headers.server:"BarracudaHTTP"
  ```
- **Brightsign Digital Sign** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22BrightSign%26reg%3B%22&page=1&indices=)               
  ```text
  http.title:"BrightSign&reg;"
  ```
- **Canon** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22Canon%20HTTP%20Server%22&page=1&indices=)     
  ```text
  http.headers.server:"Canon HTTP Server"
  ```
- **Carel PlantVisor** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22CAREL%20Pl%40ntVisor%22&page=1&indices=)              
  ```text
  http.title:"CAREL Pl@ntVisor"
  ```
- **Cisco** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name:%22Cisco%22&indices=&page=1) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name:%22Cisco%22&indices=&page=1)    
  ```text
  tag.name:"Cisco"
  ```
  ```text
  http.favicon.hash_sha256:62a8461e328d5bace3780ff738d0b58f6502592c04afa564e0a8a792583a7bfb
  ```
- **Cisco Small Business Switches** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.perceptual_hash%3Affdb0113090009ff~1%20AND%20http.body%3A%22Small%20Business%22&page=1&indices=)
  ```text
  http.favicon.perceptual_hash:ffdb0113090009ff~1 AND http.body:"Small Business"
  ```
- **Cisco XE WebUI** &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/7dU0x)
  ```text
  certificate.issuer_dn:"IOS-Self-Signed-Certificate" AND http.body:"webui"
  ```
- **Controllers with Windows CE OS** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22Microsoft-WinCE%22&page=1&indices=)     
  ```text
  http.headers.server:"Microsoft-WinCE"
  ```
- **DefectDojo** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22DefectDojo%22&page=1&indices=)    
  ```text
  http.title:"DefectDojo"
  ```
- **DLink** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22dlink%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A81adccffbd70a76e9662977e7b55938e7eec597ac8b58e5a564959e6d465deec)    
  ```text
  tag.name:"dlink"
  ```
  ```text
  http.favicon.hash_sha256:81adccffbd70a76e9662977e7b55938e7eec597ac8b58e5a564959e6d465deec
  ```
- **Draytek Routers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A0af4f089d58e919f4ee421727e9ac54d885d6b3b05ec16e4d94b703f45c7eef9)     
  ```text
  http.favicon.hash_sha256:0af4f089d58e919f4ee421727e9ac54d885d6b3b05ec16e4d94b703f45c7eef9
  ```
- **Electric vehicle charges** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22gSOAP%22%20AND%20http.content_length%3A583&page=1&indices=)       
  ```text
  http.headers.server:"gSOAP" AND http.content_length:583
  ```
- **Emerson Site Supervisor** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Emerson%20Site%20Supervisor%22&page=1&indices=)              
  ```text
  http.title:"Emerson Site Supervisor"
  ```
- **Epson HTTP**&emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22EPSON-HTTP%22&page=1&indices=)     
  ```text
  http.headers.server:"EPSON-HTTP"
  ```
- **Epson Linux** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22EPSON_Linux%20UpnP%22%20http.status_code%3A200&page=1&indices=)       
  ```text
  http.headers.server:"EPSON_Linux UpnP" http.status_code:200
  ```
- **Fortinet** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22fortinet%22&page=1) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Ad18b3c9feb76c3c1cfdcc51c732f113327e3c33fb3f63b479951f7da6ed1216f)    
  ```text
  tag.name:"fortinet"
  ```
  ```text
  http.favicon.hash_sha256:d18b3c9feb76c3c1cfdcc51c732f113327e3c33fb3f63b479951f7da6ed1216f
  ```
- **Home Assistant** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A892d336ba0b3ce7f94ebbcbe2fa5c3fcfdc79f25efcdc7a7e17918e85daaf9f0&page=1&indices=)     
  ```text
  http.favicon.hash_sha256:892d336ba0b3ce7f94ebbcbe2fa5c3fcfdc79f25efcdc7a7e17918e85daaf9f0
  ```
- **HP iLO** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22hp_ilo%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A0c16db2ccec266761010fa53ad69e2f6aafbf6b3134730e1fa72f19daf93ed04&page=1&indices=)       
  ```text
  tag.name:"hp_ilo"
  ```
  ```text
  http.favicon.hash_sha256:0c16db2ccec266761010fa53ad69e2f6aafbf6b3134730e1fa72f19daf93ed04
  ```
- **HP Printers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A(%22HP%20HTTP%22%20%22Serial%20Number%22%20%22Built%22)&page=1&indices=)     
  ```text
  http.headers.server:("HP HTTP" "Serial Number" "Built")
  ```
- **Huawei Routers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22huawei_router%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Ae64086f94c7013d92ca6d7e05933f4fb90cf8966aeff1efc583a92d1827093db)     
  ```text
  tag.name:"huawei_router"
  ```
  ```text
  http.favicon.hash_sha256:e64086f94c7013d92ca6d7e05933f4fb90cf8966aeff1efc583a92d1827093db
  ```
- **Ivanti Connect Secure** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.body%3A%22welcome.cgi%3Fp%3Dlogo%22&page=1&indices=)       
  ```text
  http.body:"welcome.cgi?p=logo"
  ```
- **Lexmark printers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22Lexmark%22&page=1&indices=)  
  ```text
  http.headers.server:"Lexmark"
  ```
- **Media servers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.category%3A%22Media%20servers%22&page=1&indices=)     
  ```text
  tag.category:"Media servers"
  ```
- **Mitsubishi Air Conditioning Control System** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A055c1bfeac57280906a11333c72430893014329296751f398939987e11d7df5c)     
  ```text
  http.favicon.hash_sha256:055c1bfeac57280906a11333c72430893014329296751f398939987e11d7df5c
  ```
- **Netgear** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22netgear%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A3bfc11a176b9c8a39870478951fc177a3bc53c9fb689cdf5f80bff6a0c4c3c6b)    
  ```text
  tag.name:"netgear"
  ```
  ```text
  http.favicon.hash_sha256:3bfc11a176b9c8a39870478951fc177a3bc53c9fb689cdf5f80bff6a0c4c3c6b
  ```
- **Nethix Wireless Controller** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.set_cookie%3A%22NethixSession%22&page=1&indices=)                 
  ```text
  http.headers.set_cookie:"NethixSession"
  ```
- **Nexus** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A9337dace49934010c4fdbb5c2c778c16f9e42bdb3da2ac476744dcc8705025c2&page=1&indices=)   
  ```text
  http.favicon.hash_sha256:9337dace49934010c4fdbb5c2c778c16f9e42bdb3da2ac476744dcc8705025c2
  ```
- **OpenCTI** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22OpenCTI%22&page=1&indices=)    
  ```text
  http.title:"OpenCTI"
  ```
- **PaperCut MF/NG** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.meta%3A%22PaperCut%20MF%22%20OR%20http.meta%3A%22PaperCut%20NG%22&page=1&indices=)    
  ```text
  http.meta:"PaperCut MF" OR http.meta:"PaperCut NG"
  ```
- **PRTG** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(http.body%3A%22PRTG%20Network%20Monitor%22)%20AND%20(http.headers.server%3A%22prtg%22)&page=1&indices=)    
  ```text
  (http.body:"PRTG Network Monitor") AND (http.headers.server:"prtg")
  ```
- **Ruckus** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A44648ca99e1d18589d4b72b19156bf61117c09e311b9f26fa771d9acf5cf463f)     
  ```text
  http.favicon.hash_sha256:44648ca99e1d18589d4b72b19156bf61117c09e311b9f26fa771d9acf5cf463f
  ```
- **Ruijie** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A8be4899f8cbc8a9d6283d101ef5b9afa95f83bef8ba676b1e5b8cfb375d2391d)     
  ```text
  http.favicon.hash_sha256:8be4899f8cbc8a9d6283d101ef5b9afa95f83bef8ba676b1e5b8cfb375d2391d
  ```
- **Samsung old printers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22syncthru%20web%20service%22&page=1&indices=)     
  ```text
  http.title:"syncthru web service"
  ```
- **Samsung Prismview** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22Prismview%22&page=1&indices=)     
  ```text
  http.headers.server:"Prismview"
  ```
- **SecurePoint** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22securepoint%22&page=1) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Aebaaed8ab7c21856f888117edaf342f6bc10335106ed907f95787b69878d9d9e)     
  ```text
  tag.name:"securepoint"
  ```
  ```text
  http.favicon.hash_sha256:ebaaed8ab7c21856f888117edaf342f6bc10335106ed907f95787b69878d9d9e
  ```
- **Siemens** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A4f81d8e8df852d2ef27c4b1d9f211a505346ae12840a83db033db329750e7fdb&page=1&indices=)   
  ```text
  http.favicon.hash_sha256:4f81d8e8df852d2ef27c4b1d9f211a505346ae12840a83db033db329750e7fdb
  ```
- **SuperMicro BMC** &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/svQi3) [[Search&nbsp;&rarr;]](https://nt.ls/JetkR)       
  ```text
  tag.name:"supermicro_ipmi"
  ```
  ```text
  certificate.subject.organization:"Super Micro Computer" AND certificate.subject.common_name:IPMI
  ```
- **Tenda** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A9322e4def463fff36b0e180ddcf67a38853b7b729716aa5ab7a119e3a24841bc)     
  ```text
  http.favicon.hash_sha256:9322e4def463fff36b0e180ddcf67a38853b7b729716aa5ab7a119e3a24841bc
  ```
- **TPLink** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22tplink%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A9e803d05d8907cca1f7730f187707c25b0fb60f9e286e2957ab1e21cffdefde2)    
  ```text
  tag.name:"tplink"
  ```
  ```text
  http.favicon.hash_sha256:9e803d05d8907cca1f7730f187707c25b0fb60f9e286e2957ab1e21cffdefde2
  ```
- **Wazuh** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Wazuh%22&page=1&indices=)    
  ```text
  http.title:"Wazuh"
  ```
- **XEROX WorkCentre** &emsp;[[Search&nbsp;&rarr;]]()     
  ```text
  certificate.issuer.common_name:"Xerox Generic Root"
  ```
- **XZERES Wind** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.body%3A%22xzeres%20wind%22&page=1&indices=)     
  ```text
  http.body:"xzeres wind"
  ```
- **Zyxel ZyWALL** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?page=1&q=tag.name%3A%22zyxel_zywall%22) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A9a02f3cf948f9409c25070f2f057b69dda5d0aaf7fa8d056552e8bda8295ca1f)     
  ```text
  tag.name:"zyxel_zywall"
  ```
  ```text
  http.favicon.hash_sha256:9a02f3cf948f9409c25070f2f057b69dda5d0aaf7fa8d056552e8bda8295ca1f
  ```

---

## Security Applications

- **Deimos C2** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Deimos%20C2%22%20OR%20certificate.subject.organization%3A%22Acme%20Co%22%20AND%20port%3A8443&page=1&indices=)                    
  ```text
  http.title:"Deimos C2" OR certificate.subject.organization:"Acme Co" AND port:8443
  ```
- **EvilGinx2** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=jarm%3A%2220d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6%22&page=1&indices=)             
  ```text
  jarm:"20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6"
  ```
- **NanoCore** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=certificate.subject.common_name%3A%22unk%22&page=1&indices=)            
  ```text
  certificate.subject.common_name:"unk"
  ```
- **Nessus Scanner Servers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22NessusWWW%22&page=1&indices=)                  
  ```text
  http.headers.server:"NessusWWW"
  ```
- **NimPlant C2** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22NimPlant%20C2%20Server%22&page=1&indices=)             
  ```text
  http.headers.server:"NimPlant C2 Server"
  ```
- **NTOP Network Analyzers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Welcome%20to%20ntopng%22%20OR%20(http.title%3A%22Global%20Traffic%20Statistics%22%20AND%20http.headers.server%3A%22ntop%2F*%22)&page=1&indices=)             
  ```text
  http.title:"Welcome to ntopng" OR (http.title:"Global Traffic Statistics" AND http.headers.server:"ntop/*")
  ```
- **Merlin C2** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=jarm%3A%2229d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38%22&page=1&indices=)               
  ```text
  jarm:"29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38"
  ```

---

## Web cameras

- **All Web cameras** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.category%3A%22Web%20cameras%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22camera%22&page=1&indices=)     
  ```text
  tag.category:"Web cameras"
  ```
  ```text
  http.title:"camera"
  ```
- **Android IP Webcam Server** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22IP%20Webcam%20Server%22&page=1&indices=)     
  ```text
  http.headers.server:"IP Webcam Server"
  ```
- **Avigilion webcams** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Avigilon%22&page=1&indices=)     
  ```text
  http.title:"Avigilon"
  ```
- **Blue Iris** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A6e32c76e9c522baacd1362fdfacc8e47eda0f62937bb226ae38a5b8d2157f7cd&page=1&indices=)     
  ```text
  http.favicon.hash_sha256:6e32c76e9c522baacd1362fdfacc8e47eda0f62937bb226ae38a5b8d2157f7cd
  ```
- **GeoVision webcams** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22GeoHttpServer%22&page=1&indices=)     
  ```text
  http.headers.server:"GeoHttpServer"
  ```
- **Hipcam** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22hipcam%22&page=1&indices=)     
  ```text
  http.headers.server:"Hipcam"
  ```
- **i-Catcher** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22i-Catcher%20Console%22&page=1&indices=)    
  ```text
  http.headers.server:"i-Catcher Console"
  ```
- **IPCam Client** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%E2%80%9Dipcam%E2%80%B3&page=1&indices=)     
  ```text
  http.title:”ipcam″
  ```
- **Linksys** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22tm01%22&page=1&indices=)     
  ```text
  http.title:"tm01"
  ```
- **SQ-WEBCAM** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22SQ-WEBCAM%22&page=1&indices=)     
  ```text
  http.headers.server:"SQ-WEBCAM"
  ```
- **UI3 for Blue Iris** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22ui3%22&page=1&indices=)     
  ```text
  http.title:"ui3"
  ```
- **VB-M600 cameras** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%E2%80%9DVB-M600%E2%80%B3&page=1&indices=)     
  ```text
  http.title:”VB-M600″
  ```
- **Vivotek IP cameras** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A"VVTK-HTTP-Server"&page=1&indices=)     
  ```text
  http.headers.server:"VVTK-HTTP-Server"
  ```
- **Webcam 7** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22webcam%207%22&page=1&indices=)     
  ```text
  http.headers.server:"webcam 7"
  ```
- **YawCam** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22yawcam%22%20http.unknown_headers.key%3A%22mime_type%22%20http.unknown_headers.value%3A%22text%2Fhtml%22&page=1&indices=)     
  ```text
  http.headers.server:"yawcam" http.unknown_headers.key:"mime_type" AND http.unknown_headers.value:"text/html"
  ```

---

## Communication

- **Adobe Connect** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A65576e8c7a144d8f4530ee1f87f6157d3fc680a029409d874f529d05e60b9fa1&page=1&indices=)   
  ```text
  http.favicon.hash_sha256:65576e8c7a144d8f4530ee1f87f6157d3fc680a029409d874f529d05e60b9fa1
  ```
- **Gitter** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Gitter%22&page=1&indices=)   
  ```text
  http.title:"Gitter"
  ```
- **Mattermost** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22mattermost%22&page=1&indices=)   
  ```text
  http.title:"mattermost"
  ```
- **Microsoft Exchange** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22microsoft_exchange%22&page=1&indices=)    
  ```text
  tag.name:"microsoft_exchange"
  ```
- **Microsoft Teams** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A397eddf44e1bf7e557b0b4f5173da95d8fd832b6f2f10d6e41c17dc539d5a822&page=1&indices=)   
  ```text
  http.favicon.hash_sha256:397eddf44e1bf7e557b0b4f5173da95d8fd832b6f2f10d6e41c17dc539d5a822
  ```
- **RabbitMQ**  &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22rabbitmq%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A8c08be4e11537f793f06a9e6dd91aba52d43032b66d11f81fa5df7e452e52aa1)    
  ```text
  tag.name:"rabbitmq"
  ```
  ```text
  http.favicon.hash_sha256:8c08be4e11537f793f06a9e6dd91aba52d43032b66d11f81fa5df7e452e52aa1
  ```
- **Rocket.Chat** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Rocket.Chat%22&page=1&indices=)    
  ```text
  http.title:"Rocket.Chat"
  ```
- **Roundcube** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22roundcube%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A20c30fd4340308d6a4ab222acae353fc2460793ac76645bb1ef1d9d61f4f0a9e)  
  ```text
  tag.name:"roundcube"
  ```
  ```text
  http.favicon.hash_sha256:20c30fd4340308d6a4ab222acae353fc2460793ac76645bb1ef1d9d61f4f0a9e
  ```
- **Skype for Business** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22skype%22%20AND%20http.title%3A%22Skype%20for%20Business%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A7d188ade5d6bc30a4d55e83a08f4e4bafe8f71ae5af2023fc87ed9767b7dda12%20AND%20http.title%3A%22Skype%20for%20Business%22&page=1&indices=)    
  ```text
  tag.name:"skype" AND http.title:"Skype for Business"
  ```
  ```text
  http.favicon.hash_sha256:7d188ade5d6bc30a4d55e83a08f4e4bafe8f71ae5af2023fc87ed9767b7dda12 AND http.title:"Skype for Business"
  ```
- **Zimbra** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22zimbra%22&page=1&indices=)   
  ```text
  tag.name:"zimbra"
  ```

---

## Remote Access

- **All Remote access** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.category%3A%22Remote%20access%22&page=1&indices=)     
  ```text
  tag.category:"Remote access"
  ```
- **NoMachine** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(port%3A4000)%20OR%20(port%3A4010)%20OR%20(port%3A4011)%20OR%20(port%3A4022)&page=1&indices=)    
  ```text
  (port:4000) OR (port:4010) OR (port:4011) OR (port:4022)
  ```
- **OpenVPN Access Server** (and just an OpenVPN) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22OpenVPN-AS%22&page=1&indices=)       
  ```text
  http.headers.server:"OpenVPN-AS"
  ```
- **RDP** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=protocol%3Ardp&page=1&indices=)
  ```text
  protocol:rdp
  ```
- **SaltStack** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22saltstack%22&page=1&indices=)    
  ```text
  http.title:"saltstack"
  ```
- **TeamViewer** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=port%3A5938&page=1&indices=)    
  ```text
  port:5938
  ```
- **VNC** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Avnc&page=1&indices=)    
  ```text
  prot7:vnc
  ```

---

## VoIP

- **All VoIP** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.category%3A%22VoIP%22&page=1&indices=)     
  ```text
  tag.category:"VoIP"
  ```
- **MSOS** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22MSOS%22&page=1&indices=)     
  ```text
  http.headers.server:"MSOS"
  ```
- **Polycom** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22polycom%22&page=1&indices=)     
  ```text
  http.title:"polycom"
  ```
- **Siemens Openstage** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22openstage%22&page=1&indices=)     
  ```text
  http.title:"openstage"
  ```
- **Snom devices** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22snom%22&page=1&indices=)     
  ```text
  http.headers.server:"snom"
  ```
- **Tanderberg** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22tandberg%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A0ac9e427c00eea6f25562023c84ed961943d13b9d7c7665a747ab536fb9c2a73&page=1&indices=)     
  ```text
  tag.name:"tandberg"
  ```
  ```text
  http.favicon.hash_sha256:0ac9e427c00eea6f25562023c84ed961943d13b9d7c7665a747ab536fb9c2a73
  ```

---

## Storages and Databases

- **Apache Tomcat** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22apache_tomcat%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A64a3170a912786e9eece7e347b58f36471cb9d0bc790697b216c61050e6b1f08)    
  ```text
  tag.name:"apache_tomcat"
  ```
  ```text
  http.favicon.hash_sha256:64a3170a912786e9eece7e347b58f36471cb9d0bc790697b216c61050e6b1f08
  ```
- **Ceph** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A3db088b4089dee70dfd305a4e200dc72c9ad7d78ffd28ffe36608eaf46591bcd&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:3db088b4089dee70dfd305a4e200dc72c9ad7d78ffd28ffe36608eaf46591bcd
  ```
- **CouchDB** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22couchdb%22&page=1&indices=) [[Search]](https://app.netlas.io/responses/?q=http.headers.server%3A%22CouchDB%22&page=1&indices=)    
  ```text
  tag.name:"couchdb"
  ```
  ```text
  http.headers.server:"CouchDB"
  ```
- **InfluxDB** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%E2%80%9DInfluxDB%20Admin%E2%80%9D&page=1&indices=)    
    ```text
  http.title:”InfluxDB Admin”
  ```
- **Kubernetes** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Aa8576f89337c561e1128e490c6f9e074fc4069057acb8d164b62d4cb205248bc)    
  ```text
  http.favicon.hash_sha256:a8576f89337c561e1128e490c6f9e074fc4069057acb8d164b62d4cb205248bc
  ```
- **Memcached** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Amemcached%20&page=1&indices=)    
  ```text
  prot7:memcached
  ```
- **MicrosoftSQL** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Amssql&page=1&indices=)    
  ```text
  prot7:mssql
  ```
- **Minio** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Minio%22&page=1&indices=)    
  ```text
  http.title:"Minio"
  ```
- **Nextcloud** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3Abea7d85401905c569359239339770d962854ccda24f134a76f492ab58ecde9f5&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:bea7d85401905c569359239339770d962854ccda24f134a76f492ab58ecde9f5
  ```
- **OpenShift** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A28409a985f1f3322a58dc5d1af0e3f09efa5b7d193341b55b11a72711a55a3dc&page=1&indices=)    
    ```text
  http.favicon.hash_sha256:28409a985f1f3322a58dc5d1af0e3f09efa5b7d193341b55b11a72711a55a3dc
  ```
- **OpenStack** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A27b7287de853e2ea7d05cf5636d6b7c70b9fb65b2f4ce9e9fded1bb27921d839&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:27b7287de853e2ea7d05cf5636d6b7c70b9fb65b2f4ce9e9fded1bb27921d839
  ```
- **phpmyadmin** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22phpmyadmin%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Ae2905705920b2636309d785c2df3f155d6379b0aa9a44dc7831524505fa2defd)    
  ```text
  tag.name:"phpmyadmin"
  ```
  ```text
  http.favicon.hash_sha256:e2905705920b2636309d785c2df3f155d6379b0aa9a44dc7831524505fa2defd
  ```
- **PostgreSQL** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=prot7%3Apostgres&page=1&indices=)    
  ```text
  prot7:postgres
  ```
- **Redis** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=redis%3A*&page=1&indices=)
  ```text
  redis:*
  ```
- **Redis wihout authentication** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=redis.ping_response%3A%22PONG%22&page=1&indices=)               
  ```text
  redis.ping_response:"PONG"
  ```
- **Vault** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Vault%22&page=1&indices=)    
  ```text
  http.title:"Vault"
  ```

---

## Web Services

- **Apache** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22apache%22&page=1&indices=)    
  ```text
  http.headers.server:"apache"
  ```
- **IIS** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22iis%22&page=1) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=%20http.headers.server%3A%22Microsoft-IIS%22&page=1&indices=)    
  ```text
  tag.name:"iis"
  ```
  ```text
  http.headers.server:"Microsoft-IIS"
  ```
- **Nginx** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3Anginx%20&page=1&indices=)    
  ```text
  http.headers.server:"nginx"
  ```
- **SolarWinds** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22solarwinds_ftp%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A2dbf88db1be0f1305a415b0455fe258627f56aa4b6b334130707a3b1adc6dba7)    
  ```text
  tag.name:"solarwinds_ftp"
  ```
  ```text
  http.favicon.hash_sha256:2dbf88db1be0f1305a415b0455fe258627f56aa4b6b334130707a3b1adc6dba7
  ```
- **WordPress** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22wordpress%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.path%3A%22%2Fwp-content%2F%22&page=1&indices=)    
  ```text
  tag.name:"wordpress"
  ```
  ```text
  http.favicon.path:"/wp-content/"
  ```
- **WordPress (misconfigured)** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.body%3A%22The%20wp-config.php%20creation%20script%20uses%20this%20file%22&page=1&indices=)              
  ```text
  http.body:"The wp-config.php creation script uses this file"
  ```
- **Drupal** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22drupal%22&page=1&indices=)    
  ```text
  tag.name:"drupal"
  ```
- **Joomla** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22joomla%22&page=1&indices=)    
  ```text
  tag.name:"joomla"
  ```
- **Confluence** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22atlassian_confluence%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A35998ea6b404f48cdaea65529793d93c19135974f6324bf1aabebce850e469bb)    
  ```text
  tag.name:"atlassian_confluence"
  ```
  ```text
  http.favicon.hash_sha256:35998ea6b404f48cdaea65529793d93c19135974f6324bf1aabebce850e469bb
  ```
- **DokuWiki** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22dokuwiki%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A3ca2c21f1821782f2b2a29b814b7aa240862014a35fdee54d23a72575fc16ec1)    
  ```text
  tag.name:"dokuwiki"
  ```
  ```text
  http.favicon.hash_sha256:3ca2c21f1821782f2b2a29b814b7aa240862014a35fdee54d23a72575fc16ec1
  ```

---

## Developing and Monitoring

- **Apache Superset** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(http.title%3Asuperset%20http.body%3ASUPERSET_WEBSERVER*)%20OR%20http.favicon.hash_sha256%3Ae186603e51173d86bfc680eee24345d67c7a1d945a8e76dc4b218bbfabed666e&page=1&indices=)     
  ```text
  (http.title:superset http.body:SUPERSET_WEBSERVER*) OR http.favicon.hash_sha256:e186603e51173d86bfc680eee24345d67c7a1d945a8e76dc4b218bbfabed666e
  ```
- **Bamboo** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22atlassian_bamboo%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A9fac9dadbd379126f3f81ba14e4e8d911362ec766e09226504121ee2758d0f64)    
  ```text
  tag.name:"atlassian_bamboo"
  ```
  ```text
  http.favicon.hash_sha256:9fac9dadbd379126f3f81ba14e4e8d911362ec766e09226504121ee2758d0f64
  ```
- **Bugzilla** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22bugzilla%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A92307d57240ad6473bf3aa757f185ee549469bb51363be2ea824fb03c7299bf2)    
  ```text
  tag.name:"bugzilla"
  ```
  ```text
  http.favicon.hash_sha256:92307d57240ad6473bf3aa757f185ee549469bb51363be2ea824fb03c7299bf2
  ```
- **cAdvisor** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22cAdvisor%20-%20%2F%22&page=1&indices=)       
  ```text
  http.title:"cAdvisor - /"
  ```
- **Citrix Gateway** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22citrix%20gateway%22&page=1&indices=)     
  ```text
  http.title:"citrix gateway"
  ```
- **GitLab** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A72a2cad5025aa931d6ea56c3201d1f18e68a8cd39788c7c80d5b2b82aa5143ef&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:72a2cad5025aa931d6ea56c3201d1f18e68a8cd39788c7c80d5b2b82aa5143ef
  ```
- **Grafana** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A80a7f87a79169cf0ac1ed3250d7c509368190a97bc7182cd4705deb8f8c70174%20AND%20http.title%3A%22Grafana%22&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:80a7f87a79169cf0ac1ed3250d7c509368190a97bc7182cd4705deb8f8c70174 AND http.title:"Grafana"
  ```
- **Graylog** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A6d1c0130478d8645c82d039b270e7ca20e912b87489163bd5d9b1c1af95db7f8&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:6d1c0130478d8645c82d039b270e7ca20e912b87489163bd5d9b1c1af95db7f8
  ```
- **HashiCorp Consul Dashboards** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Consul%20by%20HashiCorp%22&page=1&indices=)            
  ```text
  http.title:"Consul by HashiCorp"
  ```
- **Jenkins** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22jenkins%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A4fec1ee82f0dc4a8e4e9bb26954cf54cf9bf1e6a009516cb6c49ff16924e8caa)    
  ```text
  tag.name:"jenkins"
  ```
  ```text
  http.favicon.hash_sha256:4fec1ee82f0dc4a8e4e9bb26954cf54cf9bf1e6a009516cb6c49ff16924e8caa
  ```
- **Jira** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22atlassian_jira%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A7bd6886a738297cd7bf2113d2cc3d898b9cad4079f336eb03fcd737549aea8a6%20OR%20http.favicon.hash_sha256%3A84f150bf0c8858f1eb6c1e7ccc86f3208cc5a59b496059892c3aff5e22992d27%20OR%20http.favicon.hash_sha256%3A181076e8983bc2c9fdff6d0548000cd78d1379e410f55648f2c40d6d893fa9fa&page=1&indices=)    
  ```text
  tag.name:"atlassian_jira"
  ```
  ```text
  http.favicon.hash_sha256:7bd6886a738297cd7bf2113d2cc3d898b9cad4079f336eb03fcd737549aea8a6 OR http.favicon.hash_sha256:84f150bf0c8858f1eb6c1e7ccc86f3208cc5a59b496059892c3aff5e22992d27 OR http.favicon.hash_sha256:181076e8983bc2c9fdff6d0548000cd78d1379e410f55648f2c40d6d893fa9fa
  ```
- **Kafka** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%E2%80%9Dkafka%E2%80%9D%20OR%20http.title%3A%E2%80%9DApache%20Kafka%E2%80%9D%20OR%20http.body%3A%E2%80%9Dkafka%E2%80%9D%20OR%20http.body%3A%E2%80%9DApache%20Kafka%E2%80%9D&page=1&indices=)    
  ```text
  http.title:”kafka” OR http.title:”Apache Kafka” OR http.body:”kafka” OR http.body:”Apache Kafka”
  ```
- **Laravel** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22laravel%22&page=1&indices=)    
  ```text
  tag.name:"laravel"
  ```
- **ManageEngine ServiceDesk** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22manageengine_servicedesk%22&page=1&indices=)    
  ```text
  tag.name:"manageengine_servicedesk"
  ```
- **Nagios** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(http.favicon.hash_sha256%3A8b19d77c4a4ee2d846b1918a8c75c66fa1c3285a12b1d28950e1e6b817b237d4)%20OR%20(http.favicon.hash_sha256%3A57ff1068caf7d83d9c252ae26af5f833290b917945051a90cfc4b42e4e72ac13)&page=1&indices=)    
  ```text
  (http.favicon.hash_sha256:8b19d77c4a4ee2d846b1918a8c75c66fa1c3285a12b1d28950e1e6b817b237d4) OR (http.favicon.hash_sha256:57ff1068caf7d83d9c252ae26af5f833290b917945051a90cfc4b42e4e72ac13)
  ```
- **NetData Dashboards** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22Netdata%20Embedded%20HTTP*%22&page=1&indices=)                    
  ```text
  http.headers.server:"Netdata Embedded HTTP*"
  ```
- **Node.js Express** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.x_powered_by%3A%22Express%22%20OR%20http.headres.set_cookie%3A%22connect.sid%22&page=1&indices=)    
  ```text
  http.headers.x_powered_by:"Express" OR http.headres.set_cookie:"connect.sid"
  ```
- **PandoraFMS** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A62d73ef206143e68ac686f08fc770db66aa84b21f320f4953af8bdbb6b9da50e&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:62d73ef206143e68ac686f08fc770db66aa84b21f320f4953af8bdbb6b9da50e
  ```
- **Portainer** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A8170dab248310e6d887a088e75d72116e74ce99e91782e5dc0e3ff2cc4b63c3d)    
  ```text
  http.favicon.hash_sha256:8170dab248310e6d887a088e75d72116e74ce99e91782e5dc0e3ff2cc4b63c3d
  ```
- **Prometheus** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3Ad72fc7b0bd1a4c1c4a016dfa4bfd594b2fb65a409575ec8f857864d4bdc658be&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:d72fc7b0bd1a4c1c4a016dfa4bfd594b2fb65a409575ec8f857864d4bdc658be
  ```
- **Rancher Dashboards** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Loading%26hellip%3B%22&page=1&indices=)                  
  ```text
  http.title:"Loading&hellip;"
  ```
- **Redmine** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22redmine%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A5210ac65f141394a8540d408a9b56ed64c21c6b212cb28144c874f5715be9ed1)    
  ```text
  tag.name:"redmine"
  ```
  ```text
  http.favicon.hash_sha256:5210ac65f141394a8540d408a9b56ed64c21c6b212cb28144c874f5715be9ed1
  ```
- **Sentry** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22sentry%22&page=1&indices=)    
  ```text
  tag.name:"sentry"
  ```
- **SonarQube** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22sonarqubes%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Af04d7cdd55fe15c50e78457f366afa723587cf267c28b81cbcfe44248934a82b)    
  ```text
  tag.name:"sonarqubes"
  ```
  ```text
  http.favicon.hash_sha256:f04d7cdd55fe15c50e78457f366afa723587cf267c28b81cbcfe44248934a82b
  ```
- **Swagger** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A3ed612f41e050ca5e7000cad6f1cbe7e7da39f65fca99c02e99e6591056e5837&page=1&indices=)    
  ```text
  http.favicon.hash_sha256:3ed612f41e050ca5e7000cad6f1cbe7e7da39f65fca99c02e99e6591056e5837
  ```
- **Symfony** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22symfony%22&page=1&indices=)    
  ```text
  tag.name:"symfony"
  ```
- **Terraform** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Terraform%20Enterprise%22&page=1&indices=)    
  ```text
  http.title:"Terraform Enterprise"
  ```
- **Traefik Dashboards** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Traefik%22&page=1&indices=)             
  ```text
  http.title:"Traefik"
  ```
- **Weave Scope** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Weave%20Scope%22&page=1&indices=)               
  ```text
  http.title:"Weave Scope"
  ```
- **Zabbix** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22zabbix%22&page=1&indices=) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A22b06a141c425c92951056805f46691c4cd8e7547ed90b8836a282950d4b4be2)              
  ```text
  tag.name:"zabbix"
  ```
  ```text
  http.favicon.hash_sha256:22b06a141c425c92951056805f46691c4cd8e7547ed90b8836a282950d4b4be2
  ```
- **Zend Framework** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22ZendServer%22%20OR%20http.headers.set_cookie%3A%22ZDEDebuggerPresent%22&page=1&indices=)    
  ```text
  http.headers.server:"ZendServer" OR http.headers.set_cookie:"ZDEDebuggerPresent"
  ```

---

## Other

- **GaugeTech Electricity Meters** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22EIG%20Embedded%20Web%20Server%22&page=1&indices=)             
  ```text
  http.headers.server:"EIG Embedded Web Server"
  ```
- **GeoServer** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.title%3A%22geoserver%22)     
  ```text
  http.title:"geoserver"
  ```
- **Hadoop** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Hadoop%20Administration%22&page=1&indices=)    
  ```text
  http.title:"Hadoop Administration"
  ```
- **Mein Automowers** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A2a4b14d1620a2461ac510266249624df6152f266aea2946feb9b0ec8ac8a960d)        
  ```text
  http.favicon.hash_sha256:2a4b14d1620a2461ac510266249624df6152f266aea2946feb9b0ec8ac8a960d
  ```
- **Nordex Control** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A830a18175634c591efda599c39e280d0a1e98213ffe96e9d637ebff817cbc326)    
  ```text
  http.favicon.hash_sha256:830a18175634c591efda599c39e280d0a1e98213ffe96e9d637ebff817cbc326
  ```
- **shell2http** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22shell2http%22&page=1&indices=)             
  ```text
  http.title:"shell2http"
  ```
- **Splunkd** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22splunkd%22&page=1&indices=)    
  ```text
  tag.name:"splunkd"
  ```
- **Unconfigured AdGuard** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22Setup%20AdGuard%20Home%22&page=1&indices=)                 
  ```text
  http.title:"Setup AdGuard Home"
  ```
- **VictoriaMetrics Agent** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.body%3A%22%3Ch2%3Evmagent%3C%2Fh2%3E%22&page=1&indices=)          
  ```text
  http.body:"<h2>vmagent</h2>"
  ```
- **VSphere** &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A0e3b83492fe3d83d72a60b6fb194adb9afd04466268241f5ccf700278737f74d)    
  ```text
  http.favicon.hash_sha256:0e3b83492fe3d83d72a60b6fb194adb9afd04466268241f5ccf700278737f74d
  ```

---

## 2024 Interesting CVEs

- **CVE-2024-1708, -1709** (ConnectWise ScreenConnect) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/Vbu6L)             
  ```text
  http.headers.server:"ScreenConnect"
  ```
- **CVE-2024-20356** (Costp IMC) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/WixwE)            
  ```text
  http.title:"Cisco Integrated Management Controller"
  ```
- **CVE-2024-20767** (Adobe ColdFusion) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/jl0cW)                   
  ```text
  tag.name:"adobe_coldfusion"
  ```
- **CVE-2024-20931** (Oracle WebLogic) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/P0M38)      
  ```text
  protocol:t3 OR protocol:t3s
  ```
- **CVE-2024-21006** (Oracle WebLogic) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/RrPD2)         
  ```text
  port:7001 AND protocol:t3
  ```
- **CVE-2024-21410** (MS Exchange) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/pR4S2)             
  ```text
  tag.name:"microsoft_exchange"
  ```
- **CVE-2024-21690** (Junos OS) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/CpoFo)      
  ```text
  http.title:"Juniper"
  ```
- **CVE-2024-27198, -27199** (JetBrains TeamCity) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/7DYva)               
  ```text
  http.headers.set_cookie:TCSESSIONID NOT http.body:"2023.11.3" NOT http.body:"2023.11.4"
  ```
- **CVE-2024-21677** (Atlassian Confluence) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/mghaY)                      
  ```text
  http.meta:"confluence-base-url"
  ```
- **CVE-21722, -21723, -21724, -21725, -21726** (Joomla) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/dNRpZ)                   
  ```text
  tag.name:"joomla"
  ```
- **CVE-2024-22024** (Ivanti Connect Secure) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/0AKq9)       
  ```text
  http.body:"welcome.cgi?p=logo"
  ```
- **CVE-2024-23334** (Python aiohttp) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/lrzzv)              
  ```text
  http.headers.server:"aiohttp"
  ```
- **CVE-2024-23897** (Jenkins) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/z5QU0)       
  ```text
  http.headers.x_jenkins:[0 TO 2.441]
  ```
- **CVE-2024-24919** (Check Point) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/tnMCW) [[Search]](https://nt.ls/z9fQV)        
  ```text
  http.favicon.hash_sha256:9a3a865d8911afcd95389ec701e5e8abcad69d928efd5b52b5d0bcc70a60d11a
  ```
  ```text
  tag.name:"checkpoint"
  ```
- **CVE-2024-26026, -21793** (F5 BigIP) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/ptJHt)                
  ```text
  http.headers.server:"BigIP"
  ```
- **CVE-2024-26304, -26305, -33511, -33512** (ArubaOS) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/myG4Y)             
  ```text
  http.favicon.hash_sha256:dfa04944308ed6c96563ff88cdb767ed5177c76c8a386f7a5803b534e9bff753
  ```
- **CVE-2024-2879** (LayerSlider) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/8CmgD)                     
  ```text
  http.body:"plugins/layerslider"
  ```
- **CVE-2024-29895, -25641, -31445, -31459** (Cacti) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/dxZnI)                    
  ```text
  http.title:"Login to Cacti" OR http.headers.set_cookie:"Cacti"
  ```
- **CVE-2024-31136** (JetBrains TeamCity) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/HmnT2)               
  ```text
  tag.name:"teamcity"
  ```
- **CVE-2024-3273** (D-Link NAS) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/TyD6H)            
  ```text
  http.body:"Text:In order to access the ShareCenter"
  ```
- **CVE-2024-3400** (Palo Alto Networks PAN-OS) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/eprag)                 
  ```text
  tag.name:"palo_alto"
  ```
- **CVE-2024-43770** (Roundcube) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/LAQwc)           
  ```text
  http.favicon.hash_sha256:20c30fd4340308d6a4ab222acae353fc2460793ac76645bb1ef1d9d61f4f0a9e
  ```
- **CVE-2024-4835** (GitLab) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/xmir8)                
  ```text
  http.meta:"Gitlab"
  ```
- **CVE-2024-49606** (Tinyproxy) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/vWqHD)                     
  ```text
  http.headers.server:"tinyproxy/1.11.1" OR http.headers.server:"tinyproxy/1.10.0"
  ```

---

## 2023 Interesting CVEs

- **CVE-2023-2030, -5356, -7028** (GitLab Multiple vulnerability) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/IZZxE)       
  ```text
  http.meta:"Gitlab"
  ```
- **CVE-2023-20159, -20160, -20161, -20189** (Cisco Small Business Switches) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.perceptual_hash%3Affdb0113090009ff~1%20AND%20http.body%3A%22Small%20Business%22&page=1&indices=)     
  ```text
  http.favicon.perceptual_hash:ffdb0113090009ff~1 AND http.body:"Small Business"
  ```
- **CVE-2023-20198** (Cisco XE WebUI) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/7dU0x)     
  ```text
  certificate.issuer_dn:"IOS-Self-Signed-Certificate" AND http.body:"webui"
  ```
- **CVE-2023-21887, -46805** (Ivanti Connect Secure) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/I0nJC)        
  ```text
  http.body:"welcome.cgi?p=logo"
  ```
- **CVE-2023-22515** (Attlassian Confluence Data and Server) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/MwYfk) [[Alt&nbsp;&rarr;]](https://nt.ls/nysj9)     
  ```text
  tag.name:"atlassian_confluence"
  ```
  ```text
  http.meta:"confluence-base-url"
  ```
- **CVE-2023-22527** (Atlassian Confluence) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/e0S6w)       
  ```text
  http.meta:"confluence-base-url"
  ```
- **CVE-2023-22620** (SecurePoiunt) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Aebaaed8ab7c21856f888117edaf342f6bc10335106ed907f95787b69878d9d9e)    
  ```text
  http.favicon.hash_sha256:ebaaed8ab7c21856f888117edaf342f6bc10335106ed907f95787b69878d9d9e
  ```
- **CVE-2023-24411** (WordPress plugin) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=%28tag.name%3A%22wordpress%22%29%20AND%20%28prot7%3Ahttp%29%20AND%20%28http.body%3A%22wp-content%2Fplugins%2Fbne-testimonials%22%29&page=1&indices=)    
  ```text
  (tag.name:"wordpress") AND (prot7:http) AND (http.body:"wp-content/plugins/bne-testimonials")
  ```
- **CVE-2023-25135** (vBulletin) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.vbulletin.version%3A%3C%3D5.6.9&page=1&indices=)    
  ```text
  tag.vbulletin.version:<=5.6.9
  ```
- **CVE-2023-25157** (GeoServer) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.title%3A%22geoserver%22)      
  ```text
  http.title:"geoserver"
  ```
- **CVE-2023-25690** (Apache HTTP Server) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/Cl0aL)    
  ```text
  tag.apache.version:>=2.4.0 AND tag.apache.version:<=2.4.55
  ```
- **CVE-2023-25717** (Ruckus Wireless Admin) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A44648ca99e1d18589d4b72b19156bf61117c09e311b9f26fa771d9acf5cf463f)     
  ```text
  http.favicon.hash_sha256:44648ca99e1d18589d4b72b19156bf61117c09e311b9f26fa771d9acf5cf463f
  ```
- **CVE-2023-26359** (Adobe ColdFusion) &emsp;[[Searc&nbsp;&rarr;]](https://app.netlas.io/responses/?q=tag.name%3A%22adobe_coldfusion%22&page=1)    
  ```text
  tag.name:"adobe_coldfusion"
  ```
- **CVE-2023-2732** (Barracuda Email Security Gateway) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22BarracudaHTTP%22&page=1&indices=)     
  ```text
  http.headers.server:"BarracudaHTTP"
  ```
- **CVE-2023-27350** (PaperCut MF/NG) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/Gp14k)    
  ```text
  (http.title:"PaperCut Login" AND (http.description:"PaperCut NG" OR http.description:"PaperCut MF")) OR (http.favicon.perceptual_hash:3e7e66667e7c6000)
  ```
- **CVE-2023-27524** (Apache Superset) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(http.title%3Asuperset%20http.body%3ASUPERSET_WEBSERVER*)%20OR%20http.favicon.hash_sha256%3Ae186603e51173d86bfc680eee24345d67c7a1d945a8e76dc4b218bbfabed666e&page=1&indices=)     
  ```text
  (http.title:superset http.body:SUPERSET_WEBSERVER*) OR http.favicon.hash_sha256:e186603e51173d86bfc680eee24345d67c7a1d945a8e76dc4b218bbfabed666e
  ```
- **CVE-2023-27997** (Fortigate VPN) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3Ad18b3c9feb76c3c1cfdcc51c732f113327e3c33fb3f63b479951f7da6ed1216f) [[Alt&nbsp;&rarr;]](https://app.netlas.io/responses/?page=1&q=tag.name%3A%22fortigate_vpn%22)      
  ```text
  http.favicon.hash_sha256:d18b3c9feb76c3c1cfdcc51c732f113327e3c33fb3f63b479951f7da6ed1216f
  ```
  ```text
  tag.name:"fortigate_vpn"
  ```
- **CVE-2023-28375** (Osprey Pumps) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%28Osprey%20Controller%29&page=1&indices=)    
  ```text
  http.title:(Osprey Controller)
  ```
- **CVE-2023-2868** (Wordpress, MStore API) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=(tag.name%3A%22wordpress%22)%20AND%20(prot7%3Ahttp)%20AND%20(http.body%3A%22wp-content%2Fplugins%2Fmstore%22)&page=1&indices=)     
  ```text
  (tag.name:"wordpress") AND (prot7:http) AND (http.body:"wp-content/plugins/mstore")
  ```
- **CVE-2023-29183** (Fortinet/FortiProxy) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/he40Q)     
  ```text
  http.favicon.hash_sha256:d18b3c9feb76c3c1cfdcc51c732f113327e3c33fb3f63b479951f7da6ed1216f
  ```
- **CVE-2023-29357** (Microsoft SharePoint Server) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/AAVOE)     
  ```text
  http.headers.microsoftsharepointteamservices:*
  ```
- **CVE-2023-33778** (Vigor Routers) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A0af4f089d58e919f4ee421727e9ac54d885d6b3b05ec16e4d94b703f45c7eef9)       
  ```text
  http.favicon.hash_sha256:0af4f089d58e919f4ee421727e9ac54d885d6b3b05ec16e4d94b703f45c7eef9
  ```
- **CVE-2023-3128** (Grafana) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.favicon.hash_sha256%3A80a7f87a79169cf0ac1ed3250d7c509368190a97bc7182cd4705deb8f8c70174%20AND%20http.title%3A%22Grafana%22&page=1&indices=)
  ```text
  http.favicon.hash_sha256:80a7f87a79169cf0ac1ed3250d7c509368190a97bc7182cd4705deb8f8c70174 AND http.title:"Grafana"
  ```
- **CVE-2023-34192** (Zimbra Collaboration Suite) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?indices=&page=1&q=http.favicon.hash_sha256%3A1afd891aacc433e75265e3ddc9cb4fc63b88259977811384426c535037711637)      
  ```text
  http.favicon.hash_sha256:1afd891aacc433e75265e3ddc9cb4fc63b88259977811384426c535037711637
  ```
- **CVE-2023-3460** (WordPress plugin, UltimateMember) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.body%3A%22wp-content%2Fplugins%2Fultimate-member%22&page=1&indices=)     
  ```text
  http.body:"wp-content/plugins/ultimate-member"
  ```
- **CVE-2023-35078, CVE-2023-35082** (Ivanti EPMM) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/QdWH7)     
  ```text
  http.headers.set_cookie:("JSESSIONID" "Path" "/mifs")
  ```
- **CVE-2023-3519,-3466,-3467** (Citrix Gateway/ADC) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/HB0b1)      
  ```text
  http.title:"Citrix ADC" OR http.title:"Citrix Gateway"
  ```
- **CVE-2023-36434** (Windows IIS Server) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/5rvmi)       
  ```text
  http.headers.server:"Microsoft-IIS"
  ```
- **CVE-2023-36630** (CloudPanel) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.title%3A%22cloudpanel%22%20NOT%20http.body%3A%222.3.1%22&page=1&indices=)      
  ```text
  http.title:"cloudpanel" NOT http.body:"2.3.1"
  ```
- **CVE-2023-36764** (Microsoft SharePoint) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/BBPrT)     
  ```text
  http.headers.microsoftsharepointteamservices:*
  ```
- **CVE-2023-38035** (Ivanti Sentry) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/CwTWz)     
  ```text
  http.body:"images/sentry-mi-logo" AND port:8443
  ```
- **CVE-2023-38204** (Adobe ColdFusion) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/adbcf)     
  ```text
  tag.name:"adobe_coldfusion"
  ```
- **CVE-2023-39143** (PaperCut MF/NG) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/ZGjrR)     
  ```text
  (http.title:"PaperCut Login" AND (http.description:"PaperCut NG" OR http.description:"PaperCut MF")) OR (http.favicon.perceptual_hash:3e7e66667e7c6000)
  ```
- **CVE-2023-39336** (Ivanti EPM) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/fSOY9)       
  ```text
  http.headers.set_cookie:("JSESSIONID" "Path" "/mifs")
  ```
- **CVE-2023-39361,-31132,-39359 and other** (Cacti) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/tTozX)         
  ```text
  http.title:"Login to Cacti"
  ```
- **CVE-2023-40176,-40177,-40572,-40573** (XWiki) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/SSzCU)     
  ```text
  http.title:"XWiki" OR http.favicon.hash_sha256:6f0fdef9a229150fbc7183a1bbb136d7b44b6df7c34369c14bebb6adae8aaf20
  ```
- **CVE-2023-40289 and other** (SuperMicro BMC) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/svQi3) [[Alt&nbsp;&rarr;]](https://nt.ls/JetkR)      
  ```text
  tag.name:"supermicro_ipmi"
  ```
  ```text
  certificate.subject.organization:"Super Micro Computer" AND certificate.subject.common_name:IPMI
  ```
- **CVE-2023-42115,-116,-117** (Exim) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/6KhLO)       
  ```text
  smtp.banner:"exim" AND port:25
  ```
- **CVE-2023-42793** (JetBrains TeamCity) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/UM6CB)      
  ```text
  http.headers.set_cookie:TCSESSIONID NOT http.body:"2023.05.4"
  ```
- **CVE-2023-43770** &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/LAQwc)       
  ```text
  http.favicon.hash_sha256:20c30fd4340308d6a4ab222acae353fc2460793ac76645bb1ef1d9d61f4f0a9e
  ```
- **CVE-2023-4596** (WordPress, Forminator Plugin) &emsp;[[Search&nbsp;&rarr;]](https://nt.ls/3Tgzc)     
  ```text
  http.body:"/wp-content/plugins/forminator"
  ```
- **CVE-2023-46849,-46850** (OpenVPN Access Server) &emsp;[[Search&nbsp;&rarr;]](https://app.netlas.io/responses/?q=http.headers.server%3A%22OpenVPN-AS%22&page=1&indices=)       
  ```text
  http.headers.server:"OpenVPN-AS"
  ```
