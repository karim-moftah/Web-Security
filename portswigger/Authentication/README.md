## Authentication vulnerabilities



### [Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

**Goal** :  login into the website by brute-force usernames and passwords

-  go to the login page , submit any credentials , intercept the request, and send it to the intruder
-  select the value of username and click `add §`

![](./auth_img/auth1_3.png)



- from options menu , load the [usernames ](https://portswigger.net/web-security/authentication/auth-lab-usernames)wordlist . 
- check the length of the response , you will notice that all similar lengths gives you invalid username except one with unique length gives you Incorrect password . this means that this user is exist (user enumeration)

<img src="./auth_img/auth1_4.png" style="zoom:100%;" />



- repeat these steps with value of password . load the [passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) wordlist and check the response lengths

![](./auth_img/auth1_5.png)



- Only one response will have a `302` HTTP response status code, which means that the password is correct 





------



### [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

**Goal** :  login into `carlos` account by bypassing 2FA

-  go to the login page ,submit your valid credentials `wiener:peter`,intercept the request and send it to the repeater
-  you will notice that when you enter : 
   - wrong credentials , it gives `Invalid username or password.`
   - valid credentials , it redirects to `/login2` and generate security code

-  click `Email client` to get the security code and login to your account
-  logout and login with `carlos:montoya` 
-  change the URL from `/login2` to `/my-account`



------





### [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

**Goal** : reset Carlos's password then log in and access his "My account" page.

- go to the login page ,submit your valid credentials `wiener:peter`,intercept the request and send it to the repeater
- you will notice that when you enter : 

  - wrong credentials , it gives `Invalid username or password.`
  - valid credentials , it redirects to ` /my-account`
- logout and click forget password ,enter your username `peter` , go to **Email client** to get the password reset link

```apl
https://your-own.web-security-academy.net/forgot-password?temp-forgot-password-token=FiakmpwsOuDA1Ao6mrp6ivtJYuv3galm
```



- enter your new password and intercept the request , you will notice that the username is exist 
- change the value of username to `carlos` and login with the new carlos 's password
  NOTE : you can delete the token from the request ,that means you can reset the password without any token

![](./auth_img/auth10_1.png)







------



### [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

**Goal** :  login into the website by brute-force usernames and passwords

-  go to the login page ,submit any credentials ,intercept the request and send it to the intruder
-  select the value of username ,password and click `add §`
-  choose attack type `cluster bomb`  because now we have two payloads

![](./auth_img/auth2_1.png)



- from options menu , load the [usernames ](https://portswigger.net/web-security/authentication/auth-lab-usernames) and  [passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) wordlists . 

![](./auth_img/auth2_2.png)





<img src="./auth_img/auth2_3.png"  />

- All responses will give an `invalid username or password`, except only one response will have a `302` HTTP response status code, which means that the username and password are correct

![](./auth_img/auth2_4.png)









------







### [Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

**Goal** :  login into the website by brute-force usernames and passwords

-  go to the login page, submit any credentials, intercept the request and send it to the intruder.
-  select the value of username and click `add §`
-  you will notice that only the first 3 requests give `Invalid username or password.` and the other gives `You have made too many incorrect login attempts. Please try again in 30 minute(s).` , that means the web application blocks you after 3 wrong credential attempts 

![](./auth_img/auth3_1.png)



- You can bypass this by spoofing your IP with an `X-Forwarded-For` header 

- You may notice that in the case of submitting your own username, the response time changes depending on the length of the password.

- From the intruder, select the value of `X-Forwarded-For` as the first payload, the value of username as the second payload, and select `pitchfork` attack type.

![](./auth_img/auth3_2.png)



- From the options menu, set the payload type as `numbers` for the payload set 1, with a number range of 1–100 to change in each request

![](./auth_img/auth3_3.png)





- From the options menu, set the payload type as a `simple list` For payload set 2, load the [usernames ](https://portswigger.net/web-security/authentication/auth-lab-usernames) wordlist



![](./auth_img/auth3_4.png)



- Click `Start Attack`, then click Columns and select the Response received and Response completed options.
- You will notice that the username `ag` response time is longer than the others. Note: the first request (request 0) has the largest response time is my own username (`wiener`), so ignore it.



![](./auth_img/auth3_5.png)



- Set the `username= ag` and load the [passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) wordlist . 

![](./auth_img/auth3_6.png)





![](./auth_img/auth3_7.png)



- click `start attack` , all responses will give Invalid username or password except only one response will have 302 HTTP response status code which means that the username and password is correct 

![](./auth_img/auth3_8.png)









------







### [Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

**Goal** :  login into the website by brute-force usernames and passwords

-  go to the login page ,submit any credentials ,intercept the request and send it to the intruder
-  select the value of username and click `add §`
-  you will notice that when you enter : 
   - nonexistent username ,it gives `Invalid username`
   - wrong password for exist user , it gives `Incorrect password`
   - more than 2 wrong attempts,  it gives `You have made too many incorrect login attempts. Please try again in 1 minute(s).`



![](./auth_img/auth4_1.png)



- so , you can bypass the block by entering 2 wrong credentials followed by 1 valid credentials (your own username and password)

- create file contains your own username and your target username but repeat them 100 times

- create file contains  [passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) wordlist and put your password before each one.
  you can use this python script to generate the password file  

  ```python
  with open('password.txt') as f:
      lines = f.readlines()
  
  f= open('password.txt', 'w')
  for line in lines:
      c = "\npeter".join(line.split('\n'))
      f.write('\n'.join(c.split('\n')))
      f.write('\n')
  
  f.close()
  ```

- configure the intruder , load the username and password files 



![](./auth_img/auth4_2.png)



![](./auth_img/auth4_3.png)



![](./auth_img/auth4_4.png)

- click `start attack` , only one response for `carlos` will have 302 HTTP response status code which means that the username and password is correct 



![](./auth_img/auth4_5.png)





------







### [Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)





**Goal** :  login into  the website by brute-force usernames and passwords

-  go to the login page ,submit any credentials ,intercept the request and send it to the intruder
-  select the value of username ,password and click `add §`
-  choose attack type `cluster bomb`  because now we have two payloads
-  from options menu , load the [usernames ](https://portswigger.net/web-security/authentication/auth-lab-usernames) and  [passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) wordlists . 
-  responses give `Invalid username or password.` and after a lot of wrong attempts give `You have made too many incorrect login attempts. Please try again in 1 minute(s).` which means the username is valid but the account is locked 

![](./auth_img/auth5_1.png)







![](./auth_img/auth5_2.png)



- I continued the attack and I had `302` response code but you can use sniper attack with the valid username and the password wordlist



![](./auth_img/auth5_3.png)





------



### [2FA broken logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

**Goal** :  login into `carlos` account by bypassing 2FA

- go to the login page ,submit your valid credentials `wiener:peter`,intercept the request and send it to the repeater

- you will notice that when you enter : 

  - wrong credentials , it gives `Invalid username or password.`

  - valid credentials , it redirects to `/login2` and generate security code with `verify` parameter and wiener as a value in cookie 

  - ```bash
    Cookie: session=cixHQ2yF0uvG6QUOqRkyUnjsIpFlwQu6; verify=wiener
    ```

- change `wiener` to `carlos` and send `GET` request to `/login2` to generate security code for `carlos`

- brute-force the security code with burp intruder

![](./auth_img/auth7_2.png)





![](./auth_img/auth7_3.png)



- you can use simple list payload type and load the output from this script which generates numbers in 4 digits from 0-9999

```python
for i in range(0,10000):
    print(f"{str(i).zfill(4)}")
```





- start the attack and you will get`302` response code 
- Right-click on the response and select `Show response in browser`. Copy the URL and load it in the browser. The page loads and you are logged in as `carlos`

![](./auth_img/auth7_4.png)





------
