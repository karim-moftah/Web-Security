# Recon Tools



### Subdomain enumeration tools

####  github tools

- [Sublist3r](https://github.com/aboul3la/Sublist3r)

  ```bash
  python sublist3r.py -d <domain> 
  ```

- [subfinder](https://github.com/projectdiscovery/subfinder)

  ```bash
  subfinder -d <domain> 
  ```

- [assetfinder](https://github.com/tomnomnom/assetfinder)

  ```bash
  assetfinder --subs-only <domain>
  ```

- [amass](https://github.com/OWASP/Amass)

  > Configuring API keys

  To use external API we’ll need to configure the respective keys and place them in the config.ini file located in ~/amass. The project’s GitHub page has a sample [config.ini file](https://github.com/OWASP/Amass/blob/master/examples/config.ini).

  ```bash
  amass intel -d <domain>
  amass intel -org uber
  amass intel -ip -src -cidr 104.154.0.0/15
  amass intel -asn 63086
  amass enum -ip -d <domain>
  amass enum –list
  amass enum -passive -d <domain>
  amass enum -active -d <domain>
  ```

- [Findomain](https://github.com/Findomain/Findomain)

  > Configuring API keys [API ](https://github.com/Findomain/Findomain/blob/master/docs/INSTALLATION.md#access-tokens-configuration)

  ```bash
  findomain -t example.com
  ```

- [altdns](https://github.com/infosec-au/altdns)

  ```bash
  altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt
  ```

- [domains-from-csp](https://github.com/0xbharath/domains-from-csp)

  ```
  python csp_parser.py target_url
  ```

  

#### websites

- https://pentest-tools.com/
- https://virustotal.com/
- https://www.shodan.io/
- [https://crt.sh/?q=%25taregt.com](https://crt.sh/?q=%taregt.com)
- https://dnsdumpster.com/
- [https://censys.io](https://censys.io/)
- [http://dnsgoodies.com](http://dnsgoodies.com/)
- https://bitbucket.org/LaNMaSteR53/recon-ng
- http://securitytrails.com/

- https://community.riskiq.com/home
- https://urlscan.io/



### Port Scanning tools

- [masscan](https://github.com/robertdavidgraham/masscan)

  ```bash
  masscan -iL masscan.in -oG masscan.out --open --max-rate 30000 -p 0-65535
  ```

- nmap

- [RustScan](https://github.com/RustScan/RustScan)


### Directory Scanning

- [dirsearch](https://github.com/maurosoria/dirsearch)
- dirb
- gobuster
- [ffuf](https://github.com/ffuf/ffuf)



### **Discovering Target Using ASN (IP Blocks):**

- [http://bgp.he.net](http://bgp.he.net/)
- https://whois.arin.net/ui/query.do

- https://apps.db.ripe.net/db-web-ui/#/fulltextsearch

- https://reverse.report/

- [https://www.shodan.io/search?query=org%3A%22Tesla+Motors%22](https://www.shodan.io/search?query=org%3A"Tesla+Motors")




### Acquisition 

- [**crunchbase**](https://www.crunchbase.com/search/acquisitions)



### live subdomains

- httpx
- httprobe



### Detect WAF tools

- [wafw00f](https://github.com/sandrogauci/wafw00f)

  ```bash
  wafw00f https://example.org
  ```

- [whatwaf](https://github.com/Ekultek/WhatWaf)

  ```bash
  ./whatwaf -u URL
  ```

- [bypass-firewalls-by-DNS-history](https://github.com/vincentcox/bypass-firewalls-by-DNS-history)

  ```bash
  bash bypass-firewalls-by-DNS-history.sh -d example.com
  ```



### Subdomain Takeover

- [SubOver](https://github.com/Ice3man543/SubOver)
- [subjack](https://github.com/haccer/subjack)
- [subzy](https://github.com/LukaSikic/subzy)
- [*can-i-take-over-xyz*](https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md)



### secreenshot

- [aquatone](https://github.com/michenriksen/aquatone)

  ```bash
  echo "aquatone-discover -d \$1 && aquatone-scan -d \$1 --ports huge && aquatone-takeover -d \$1 && aquatone-gather -d \$1" >> aqua.sh && chmod +x aqua.sh
  
  ./aqua.sh domain.com
  ```

- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)

  ```bash
  ./EyeWitness -f urls.txt --web
  ```

  

### s3 bucket

- [sandcastle](https://github.com/yasinS/sandcastle)
- [Bucket Finder](https://digi.ninja/projects/bucket_finder.php)
- [S3Scanner](https://github.com/sa7mon/S3Scanner)
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)



### Google Dorks

- https://www.exploit-db.com/google-hacking-database
- https://dorks.faisalahmed.me/#
- https://pentest-tools.com/information-gathering/google-hacking
- https://github.com/1N3/Goohak/
- https://github.com/obheda12/GitDorker
- https://github.com/ZephrFish/GoogD0rker/
- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06
- https://gist.github.com/stevenswafford/393c6ec7b5375d5e8cdc
- https://github.com/BullsEye0/google_dork_list/blob/master/google_Dorks.txt
- https://github.com/CorrieOnly/google-dorks
- https://securitytrails.com/blog/google-hacking-techniques



### Shodan Dorks

- net:<CIDR>
- http.title:"example" 200
- ssl.cert.subjct.CN:"domain.com" 200
- ssl: HackerOne Inc " 200 
- domain.com internal
- https://securitytrails.com/blog/top-shodan-dorks



### Github Dorks

- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [gitrob](https://github.com/michenriksen/gitrob)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets)
- https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt



### Wayback Enumeration

- https://archieve.org/web
- [waybackurls](https://github.com/tomnomnom/waybackurls)



### **Parsing links from Javascript files**

- [JSParser](https://github.com/nahamsec/JSParser)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)



### Parameter brute-forcing

- [Arjun](https://github.com/s0md3v/Arjun)
- [Parameth](https://github.com/maK-/parameth)
- [Brutespray](https://github.com/x90skysn3k/brutespray)




### collect users & emails

- hunter.io

- userrecon

- haveibeenpwned

- https://github.com/maldevel/EmailHarvester

- https://github.com/m4ll0k/Infoga

- https://www.skymem.info/

- https://github.com/joeyism/linkedin_scraper

- https://github.com/ChrisAD/linkedin-employee-scraper



### leaked database

- sunbase.com

- dehashed.com

- intelx.io
- https://weleakinfo.com/

- https://breached.to/
- https://github.com/sm00v/Dehashed
- @shi_ver_bot  (telegram)

- @meganzshare (telegram)

- https://web.archive.org/web/20190118172835/https://databases.today/




### wordlists

- [SecLists](https://github.com/danielmiessler/SecLists)

- [Jhaddix Content_discovery_all.txt](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
- https://wordlists.assetnote.io/



###  Identify

- [Wappalyzer](https://www.wappalyzer.com/) 
- [Builtwith](https://builtwith.com/)



### Recon Framework

- rengine

- reconftw



### vulnerability scanner

- nuclie
- netsparker
- acuentix
- Web inspect
- W3af



### other tools

https://github.com/lc/gau

https://github.com/tomnomnom/anew

https://github.com/stedolan/jq

https://github.com/tomnomnom/gf 

https://github.com/1ndianl33t/Gf-Patterns

https://github.com/laluka/bypass-url-parser

### Useful websites

- https://pentestbook.six2dez.com/

- https://bugbountyforum.com/tools/recon/

- https://pentester.land/cheatsheets/2019/04/15/recon-resources.html
