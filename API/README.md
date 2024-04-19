# API Penetration Testing



## Table of Contents

- [Passive API recon](#passive-api-recon)
- [Active API recon](#active-api-recon)
- [Endpoint Analysis: Reverse Engineering an API](#endpoint-analysis)
  - [1. Building a Collection in Postman with postman proxy](#1-building-a-collection-in-postman-with-postman-proxy)
  - [2. Automatic Documentation with mitmweb ](#2-automatic-documentation-with-mitmweb)
- [API Authentication Attacks](#api-authentication-attacks)
  - [1. Password Brute-Force Attacks](#1-password-brute-force-attacks)
  - [2. Password Spraying](#2-password-spraying)
  - [3. Token Analysis](#3-token-analysis)
  - [4. JWT Attacks](#4-jwt-attacks)
  - [Automating JWT attacks with JWT_Tool](#automating-jwt-attacks-with-jwt_tool)
- [API Authorization Attacks](#api-authorization-attacks)
  - [Broken Object Level Authorization (BOLA)](#broken-object-level-authorization-bola)
  - [Broken Function Level Authorization (BFLA)](#broken-function-level-authorization-bfla)
- [Improper Assets Management](#improper-assets-management)
- [Mass Assignment Attacks]

<br />

<br />

---

## Passive API recon

### 1. Google dorks

- intitle:"api" site:target.com
- inurl:"/api" site:target.com
- intitle:"swagger" site:target.com
- filename:"swagger.json" site:target.com
- inurl:"/wp-json/wp/v2/users"
- intitle:"index.of" intext:"api.txt"
- inurl:"/api/v1" intext:"index of /"
- ext:php inurl:"api.php?action="
- intitle:"index of" api_key OR "api key" OR apiKey -pool

<br />



### 2. Shodan

- hostname:"targetname.com"
- "content-type: application/json"
- "content-type: application/xml"
- "wp-json"

<br />

### 3. **The Wayback Machine**

<br />

---



## Active API recon

### 1. nmap

```bash
nmap -sC -sV 127.0.0.1
nmap -p- 127.0.0.1
nmap -sV --script=http-enum <target> -p 80,443,8000,8080
```

<br />

### 2. amass

```bash
amass enum -active -d target.com | grep "api"
 amass enum -active -brute -w /usr/share/wordlists/API_superlist -d [target domain] -dir [directory name]  
```

<br />

### 3. Directory bruteforce

```bash
gobuster
dirb
```

<br />

### 4. **Kiterunner**

Kiterunner is an excellent tool that was developed and released by Assetnote. Kiterunner is currently the best tool available for discovering API endpoints and resources. While directory brute force tools like Gobuster/Dirbuster/ work to discover URL paths, it typically relies on standard HTTP GET requests. Kiterunner will not only use all HTTP request methods common with APIs (GET, POST, PUT, and DELETE) but also mimic common API path structures. In other words, instead of requesting GET /api/v1/user/create, Kiterunner will try POST /api/v1/user/create, mimicking a more realistic request.

You can perform a quick scan of your target’s URL or IP address like this:

```bash
$ kr scan HTTP://127.0.0.1 -w ~/api/wordlists/data/kiterunner/routes-large.kite
$ kr brute <target> -w ~/api/wordlists/data/automated/nameofwordlist.txt
```

<br /><br />

---

## Endpoint Analysis

### Reverse Engineering an API

<br />

### 1. Building a Collection in Postman with postman proxy

In the instance where there is no documentation and no specification file, you will have to reverse-engineer the API based on your interactions with it. Mapping an API with several endpoints and a few methods can quickly grow into quite a large attack surface. To manage this process, build the requests under a collection in order to thoroughly hack the API. Postman can help you keep track of all of these requests. There are two ways to manually reverse engineer an API with Postman. One way is by constructing each request. While this can be a bit cumbersome, it will allow you to add the precise requests you care about. The other way is to proxy web traffic through Postman, and then use it to capture a stream of requests. This process makes it much easier to construct requests within Postman, but you’ll have to remove or ignore unrelated requests. Later in this module, we'll review a great way to automatically document APIs with mitmproxy2swagger.

First, let's launch Postman.

```bash
$ postman
```



Next, create a Workspace to save your collections in. For this course, we will use the ACE workspace. 

To build your own collection in Postman with the Proxy, use the Capture Requests button, found at the bottom right of the Postman window. 

![img](./assets/1.PNG)

<br />

In the Capture requests window, select Enable proxy. The port should match with the number that is set up in FoxyProxy (5555). Next, enable the Postman Proxy, add your target URL to the "URL must contain" field, and click the Start Capture button.

![img](./assets/2.PNG)

<br />

Open up your web browser, navigate to crAPI's landing page, and use FoxyProxy to enable the Postman option. Now you can meticulously use the web app as intended. Meticulous, because you want to capture every single bit of functionality available within the application. This means using all of the features of the target. Click on links, register for an account, sign in to the account, visit your profile, post comments in a forum, etc. Essentially click all the things, update information where you can, and explore the web app in its entirety. How thorough you use the web app will have a domino effect on what endpoints and requests you will later test. For example, if you were to perform the various actions of the web app, but forgot to test the community endpoints then you will have a blindspot in the API attack surface. 

![img](./assets/3.PNG)

<br />

For example, make sure to perform all of the actions on the my-profile page:

- add a profile picture
- upload a personal video
- change the account email address
- use the three horizontal dots to find additional options to:
  - change video
  - change video name
  - share video with community

Also, use the crAPI MailHog server to get the most out of this app. The MailHog server is located on port 8025 and will be used for registering user vehicles, resetting passwords, and where "change email" tokens are sent.

![img](./assets/4.PNG)

 

<br />

Once you have captured all of the features you can find with manual exploration then you will want to Stop the Proxy. Next, it is time to build the crAPI collection. First, create a new collection by selecting the new button (top left side of Postman) and then choose Collection.

![img](./assets/5.PNG)

<br />

Go ahead and rename the collection to **crAPI Proxy Collection**. Navigate back to the Proxy debug session and open up the Requests tab.

![img](./assets/6.PNG)

<br />

Select all of the requests that you captured and use the "add to Collection" link highlighted above. Select the crAPI Proxy Collection and organize the requests by Endpoints. With all of the captured requests added to the crAPI Proxy Collection, you can organize the collection by renaming all of the requests and grouping similar requests into folders. Before you get too far into this exercise, I would recommend checking out the automated documentation instructions below. 

<br />

<br />

## 2. Automatic Documentation with mitmweb 

First, we will begin by proxying all web application traffic using mitmweb.

Simply use a terminal and run:

```bash
$ mitmweb
```





![img](./assets/7.png)

<br />

This will create a proxy listener using port 8080. You can then open a browser and use FoxyProxy to proxy your browser to port 8080 using our Burp Suite option.

![img](./assets/8.png)

<br />

Once the proxy is set up, you can once again use the target web application as it was intended.

*Note: if you are reverse engineering crapi.apisec.ai you may run into certificate issues if you have not yet added the mitmweb cert. Please return back to Kali Linux and More MITMweb Certificate Setup for instructions.*

Every request that is created from your actions will be captured by the mitmweb proxy. You can see the captured traffic by using a browser to visit the mitmweb web server located at http://127.0.0.1:8081.

![img](./assets/9.png)

 

<br />

Continue to explore the target web application until there is nothing left to do. Once you have exhausted what can be done with your target web app, return to the mitmweb web server and click **File > Save** to save the captured requests.

![img](./assets/10.png)

<br />

Selecting **Save** will create a file called flows. We can use the "flows" file to create our own API documentation. Using a great tool called mitmproxy2swagger, we will be able to transform our captured traffic into an Open API 3.0 YAML file that can be viewed in a browser and imported as a collection into Postman.

First, run the following:

```bash
$sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://crapi.apisec.ai -f flow
```



![img](./assets/11.png)

<br />

After running this you will need to edit the spec.yml file to see if mitmproxy2swagger has ignored too many endpoints. Checking out spec.yml reveals that several endpoints were ignored and the title of the file can be updated. You can use Nano or another tool like Sublime to edit the spec.yml.

![img](./assets/12.PNG)

<br />

Update the YAML file so that "ignore:" is removed from the endpoints that you want to include. If you're are using Sublime, you can simply select all of the endpoints that you want to edit (hold CTRL while selecting) and then use (CTRL+Shift+L) to perform a simultaneous multi-line edit.
![img](./assets/13.PNG)

 <br />

Make sure to **only remove "ignore:"**. Removing spacing or the "-" can result in the script failing to work. 

![img](./assets/14.PNG)

 <br />

Note that the "title" has been updated to "crAPI Swagger" and that the endpoints no longer contain "ignore:". Once your docs look similar to the image above, make sure to run the script once more. This second run will correct the format and spacing. This time around you can add the "--examples" flag to enhance your API documentation.

```bash
$sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://crapi.apisec.ai -f flow --examples
```





![img](./assets/15.png)

<br />

After running mitmproxy2swagger successfully a second time through, your reverse-engineered documentation should be ready. You can validate the documentation by visiting https://editor.swagger.io/ and by importing your spec file into the Swagger Editor. Use **File>Import file** and select your spec.yml file. If everything has gone as planned then you should see something like the image below. This is a pretty good indication of success, but to be sure we can also import this file as a Postman Collection that way we can prepare to attack the target API.

![img](./assets/16.png)

<br />

 To import this file as a collection we will need to open Postman. At the top left of your Postman Workspace, you can click the "Import" button. Next, select the spec.yml file and import the collection.

![img](./assets/17.png)

<br />

Once you import the file you should see a relatively straightforward API collection that can be used to analyze the target API and exploit with future attacks.

![img](./assets/18.png)

With a collection prepared, you should now be ready to use the target API as it was designed. This will enable you to see the various endpoints and understand what is required to make successful requests. In the next module, we will begin working with the API and learn to analyze various requests and responses. 

<br /><br />

---



## API Authentication Attacks



### 1. Password Brute-Force Attacks

One of the more straightforward methods for gaining access to an API is performing a brute-force attack. Brute-forcing an API’s authentication is not very different from any other brute-force attack, except you’ll send the request to an API endpoint, the payload will often be in JSON, and the authentication values may require base64 encoding.

One of the best ways to fine-tune your brute-force attack is to generate passwords specific to your target. To do this, you could leverage the information revealed in an excessive data exposure vulnerability.

For more information about creating targeted password lists, check out the 

- [Mentalist app](https://github.com/sc0tfree/mentalist) 
- [Common User Passwords Profiler](https://github.com/Mebus/cupp).

To actually perform the brute-force attack once you have a suitable wordlist, you can use tools such as Burp Suite’s Intruder or Wfuzz. The following example uses Wfuzz with an old, well-known password list, rockyou.txt. Rockyou.txt does come as a standard wordlist on Kali Linux, however, it is currently zipped with Gzip. You can unzip rockyou.txt using the following command.



Important items to note for API testing include the headers option (-H), hide responses (--hc, --hl, --hw, --hh), and POST body requests (-d). All of these will be useful when fuzzing APIs. We will need to specify the content-type headers for APIs which will be 'Content-Type: application/json'

```bash
$ wfuzz -d '{"email":"admin@email.com","password":"FUZZ"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/rockyou.txt -u http://127.0.0.1:8888/identity/api/auth/login --hc 405
```

The –hc option helps you filter out the responses you don’t want to see

<br />

---

### 2. Password Spraying

Many security controls could prevent you from successfully brute-forcing an API’s authentication. A technique called password spraying can evade many of these controls by combining a long list of users with a short list of targeted passwords. Let’s say you know that an API authentication process has a lockout policy in place and will only allow 10 login attempts. You could craft a list of the nine most likely passwords (one less password than the limit) and use these to attempt to log in to many user accounts.

When you’re password spraying, large and outdated wordlists like rockyou.txt won’t work. There are way too many unlikely passwords in such a file to have any success. Instead, craft a short list of likely passwords, taking into account the constraints of the API provider’s password policy, which you can discover during reconnaissance. 

Most password policies likely require a minimum character length, upper- and lowercase letters, and perhaps a number or special character. Use passwords that are simple enough to guess but complex enough to meet basic password requirements (generally a minimum of eight characters, a symbol, upper- and lowercase letters, and a number). The first type includes obvious passwords like QWER!@#$, Password1!, and the formula Season+Year+Symbol (such as Winter2021!, Spring2021?, Fall2021!, and Autumn2021?). 

The second type includes more advanced passwords that relate directly to the target, often including a capitalized letter, a number, a detail about the organization, and a symbol. Here is a short password-spraying list I might generate if I were attacking an endpoint for Twitter employees: Summer2022! Spring2022! QWER!@#$ March212006! July152006! Twitter@2022 JPD1976! [Dorsey@2022](mailto:Dorsey@2021) .

The real key to password spraying is to maximize your user list. The more usernames you include, the higher your odds of compromising a user account with a bad password. Build a user list during your reconnaissance efforts or by discovering excessive data exposure vulnerabilities.

<br />

**to extract mails from response**

```bash
$grep -oe "[a-zA-Z0-9._]\+@[a-zA-Z]\+.[a-zA-Z]\+" response.json | sort -u
```



<br />

---

### 3. Token Analysis

When implemented correctly, tokens can be an excellent tool that can be used to authenticate and authorize users. However, if anything goes wrong when generating, processing, or handling tokens, they can become our keys to the kingdom.

In this section, we will take a look at the process that can be used with Burp Suite to analyze tokens. Using this process can help you identify predictable tokens and aid in token forgery attacks. To analyze tokens we will take our crAPI API authentication request and proxy it over to Burp Suite.

![img](./assets/19.PNG)

<br />

Next, you will need to right-click on the request and forward it over to Sequencer. In Sequencer, we will be able to have Burp Suite send thousands of requests to the provider and perform an analysis of the tokens received in response. This analysis could demonstrate that a weak token creation process is in use.

Navigate to the Sequencer tab and select the request that you forwarded. Here we can use the Live Capture to interact with the target and get live tokens back in a response to be analyzed. To make this process work, you will need to define the custom location of the token within the response. Select the Configure button to the right of Custom Location. Highlight the token found within quotations and click OK.

![img](./assets/20.PNG)

<br />

Once the token has been defined then you can Start live capture. At this point, you can either wait for the capture to process thousands of requests or use the Analyze now button to see results sooner.

![img](./assets/21.PNG)

<br />

Using Sequencer against crAPI shows that the tokens generated seem to have enough randomness and complexity to not be predictable. Just because your target sends you a seemingly complex token, does not mean that it is safe from token forgery. Sequencer is great at showing that some complex tokens are actually very predictable. If an API provider is generating tokens sequentially then even if the token were 20 plus characters long, it could be the case that many of the characters in the token do not actually change. Making it easy to predict and create our own valid tokens.

To see what an analysis of a poor token generation process looks like perform an analysis of the "bad tokens" located on the Hacking APIs Github repository (https://raw.githubusercontent.com/hAPI-hacker/Hacking-APIs/main/bad_tokens). This time around we will use the Manual load option, to provide our own set of bad tokens. 

![img](./assets/22.PNG)

If you use the Analyze Now button and let Sequencer run its analysis. Check out the Character-level analysis which reveals that the 12 alpha-numeric token uses the same characters for the first 8 positions. The final three characters of these tokens have some variation. Taking note of the final three characters of these tokens you can notice that the possibilities consist of two lower-case letters followed by a number (aa#). With this information, you could brute-force all of the possibilities in under 7,000 requests. Then you can take these tokens and make requests to an endpoint like */identity/api/v2/user/dashboard.* Based on the results of your requests, search through the usernames and emails to find users that you would like to attack.

<br />

---

### 4. JWT Attacks

JSON Web Tokens (JWTs) are one of the most prevalent API token types because they operate across a wide variety of programming languages, including Python, Java, Node.js, and Ruby. These tokens are susceptible to all sorts of misconfiguration mistakes that can leave the tokens vulnerable to several additional attacks. These attacks could provide you with sensitive information, grant you basic unauthorized access, or even administrative access to an API. This module will guide you through a few attacks you can use to test and break poorly implemented JWTs. 

JWTs consist of three parts, all of which are base64 encoded and separated by periods: the header, payload, and signature. JWT.io is a free web JWT debugger that you can use to check out these tokens. You can spot a JWT because they consist of three periods and begin with "ey". They begin with "ey" because that is what happens when you base64 encode a curly bracket followed by a quote, which is the way that a decoded JWT always begins. 

<br />

You could use this token in requests to gain access to the API as the user specified in the payload. More commonly, though, you’ll obtain a JWT by authenticating to an API and the provider will respond with a JWT. In order to obtain a JWT from crAPI, we will need to leverage our authentication request.

![img](./assets/23.PNG)

<br />

The token we receive back from crAPI doesn't necessarily say "JWT: anywhere, but we can easily spot the "ey" and three segments separated by periods. The first step to attacking a JWT is to decode and analyze it. If we take this token and add it to the JWT debugger this is what we see.

![img](./assets/24.PNG)

<br />

In this example, we can see the algorithm is set to HS512, the email of our account, iat, exp, and the current signature is invalid. If we were able to compromise the signature secret then we should be able to sign our own JWT and potentially gain access to any valid user's account. Next, we will learn how to use automated tooling to help us with various JWT attacks.

<br />

----

### Automating JWT attacks with JWT_Tool

The JSON Web Token Toolkit or JWT_Tool is a great command line tool that we can use for analyzing and attacking JWTs. With this, we will be able to analyze JWTs, scan for weaknesses, forge tokens, and brute-force signature secrets. If you followed along during the setup module you should be able to use the jwt_tool alias to see the usage options:

```bash
$jwt_tool
```


![img](./assets/25.PNG)

As you can see, jwt_tool makes the header and payload values nice and clear. Additionally, jwt_tool has a “Playbook Scan” that can be used to target a web application and scan for common JWT vulnerabilities. You can run this scan by using the following:

```bash
$ jwt_tool -t http://target-name.com/ -rh "Authorization: Bearer JWT_Token" -M pb
```

<br />

In the case of crAPI we will run:

```bash
$jwt_tool -t http://127.0.0.1:8888/identity/api/v2/user/dashboard -rh "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYWFhQGVtYWlsLmNvbSIsImlhdCI6MTY1ODUwNjQ0NiwiZXhwIjoxNjU4NTkyODQ2fQ.BLMqSjLZQ9P2cxcUP5UCAmFKVMjxhlB4uVeIu2__6zoJCJoFnDqTqKxGfrMcq1lMW97HxBVDnYNC7eC-pl0XYQ" -M pb
```

<br />

 ![img](./assets/26.PNG)

During this scan for common misconfiguration, JWT_Tool tested the various claims found within the JWT (sub, iat, exp)

<br />

#### The None Attack

If you ever come across a JWT using "none" as its algorithm, you’ve found an easy win. After decoding the token, you should be able to clearly see the header, payload, and signature. From here, you can alter the information contained in the payload to be whatever you’d like. For example, you could change the username to something likely used by the provider’s admin account (like root, admin, administrator, test, or adm), as shown here: { "username": "root", "iat": 1516239022 } Once you’ve edited the payload, use Burp Suite’s Decoder to encode the payload with base64; then insert it into the JWT. Importantly, since the algorithm is set to "none", any signature that was present can be removed. In other words, you can remove everything following the third period in the JWT. Send the JWT to the provider in a request and check whether you’ve gained unauthorized access to the API.

<br />

#### The Algorithm Switch Attack

There is a chance the API provider isn’t checking the JWTs properly. If this is the case, we may be able to trick a provider into accepting a JWT with an altered algorithm. One of the first things you should attempt is sending a JWT without including the signature. This can be done by erasing the signature altogether and leaving the last period in place, like this: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoYWNrYXBpcy5pbyIsImV4cCI6IDE1ODM2Mzc0ODgsInVzZ XJuYW1lIjoiU2N1dHRsZXBoMXNoIiwic3VwZXJhZG1pbiI6dHJ1ZX0. If this isn’t successful, attempt to alter the algorithm header field to "none". Decode the JWT, update the "alg" value to "none", base64-encode the header, and send it to the provider. To simplify this process, you can also use the jwt_tool to quickly create a token with the algorithm switched to none.

```bash
$ jwt_tool eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYWFhQGVtYWlsLmNvbSIsImlhdCI6MTY1ODg1NTc0MCwiZXhwIjoxNjU4OTQyMTQwfQ._EcnSozcUnL5y9SFOgOVBMabx_UAr6Kg0Zym-LH_zyjReHrxU_ASrrR6OysLa6k7wpoBxN9vauhkYNHepOcrlA -X a
```

If successful, pivot back to the None attack. However, if we try this with crAPI, the attack is not successful. You can also use JWT_Tool to create a none token.

A more likely scenario than the provider accepting no algorithm is that they accept multiple algorithms. For example, if the provider uses RS256 but doesn’t limit the acceptable algorithm values, we could alter the algorithm to HS256. This is useful, as RS256 is an asymmetric encryption scheme, meaning we need both the provider’s private key and a public key in order to accurately hash the JWT signature. Meanwhile, HS256 is symmetric encryption, so only one key is used for both the signature and verification of the token. If you can discover and obtain the provider’s RS256 public key then switch the algorithm from RS256 to HS256, there is a chance you may be able to leverage the RS256 public key as the HS256 key. It uses the format jwt_tool TOKEN -X k -pk public-key.pem, as shown below. You will need to save the captured public key as a file on your attacking machine (You can simulate this attack by taking any public key and saving it as public-key-pem).

```bash
$ jwt_tool eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYWFhQGVtYWlsLmNvbSIsImlhdCI6MTY1ODg1NTc0MCwiZXhwIjoxNjU4OTQyMTQwfQ._EcnSozcUnL5y9SFOgOVBMabx_UAr6Kg0Zym-LH_zyjReHrxU_ASrrR6OysLa6k7wpoBxN9vauhkYNHepOcrlA -X k -pk public-key-pem
```

<br />

#### JWT Crack Attack

The JWT Crack attack attempts to crack the secret used for the JWT signature hash, giving us full control over the process of creating our own valid JWTs. Hash-cracking attacks like this take place offline and do not interact with the provider. Therefore, we do not need to worry about causing havoc by sending millions of requests to an API provider. You can use JWT_Tool or a tool like Hashcat to crack JWT secrets. You’ll feed your hash cracker a list of words. The hash cracker will then hash those words and compare the values to the original hashed signature to determine if one of those words was used as the hash secret. If you’re performing a long-term brute-force attack of every character possibility, you may want to use the dedicated GPUs that power Hashcat instead of JWT_Tool. That being said, JWT_Tool can still test 12 million passwords in under a minute. First, let's use Crunch, a password-generating tool, to create a list of all possible character combinations to use against crAPI.

```bash
$crunch 5 5 -o crAPIpw.txt
```



![img](./assets/27.PNG)

<br />

We can use this password file that contains all possible character combinations created for 5 character passwords against our crAPI token. To perform a JWT Crack attack using JWT_Tool, use the following command: 

```bash
$ jwt_tool TOKEN -C -d wordlist.txt
```

<br />

 The -C option indicates that you’ll be conducting a hash crack attack, and the -d option specifies the dictionary or wordlist you’ll be using against the hash. JWT_Tool will either return “CORRECT key!” for each value in the dictionary or indicate an unsuccessful attempt with “key not found in dictionary.”

![img](./assets/28.PNG)

<br />

Now that we have the correct secret key that is used to sign crAPI's tokens, we should be able can generate our own trusted tokens. To test out our new abilities, you can either create a second user account in crAPI or use an email that you have already discovered. I have created an account named "superadmin".

<br />

![img](./assets/29.PNG)

<br />

You can add your user token to the JWT debugger, add the newly discovered secret, and update the "sub" claim to any email that has registered to crAPI.

![img](./assets/30.PNG)



<br />

Use the token that you generated in the debugger and add it to your Postman Collection. Make a request to an endpoint that will prove your access such as GET /identity/api/v2/user/dashboard. 

![img](./assets/31.PNG)



<br /><br />

---



## API Authorization Attacks

An API’s authentication process is meant to validate that users are who they claim to be. An API's authorization is meant to allow users to access the data they are permitted to access. In other words, UserA should only be able to access UserA's resources and UserA should not be able to access UserB's resources. API providers have been pretty good about requiring authentication when necessary, but there has been a tendency to overlook controls beyond the hurdle of authentication. Authorization vulnerabilities are so common for APIs that the OWASP security project included two authorization vulnerabilities on its top ten list, `Broken Object Level Authorization (BOLA)` and `Broken Function Level Authorization (BFLA)`.

RESTful APIs are stateless, so when a consumer authenticates to these APIs, no session is created between the client and server. Instead, the API consumer must prove their identity within every request sent to the API provider’s web server. 

 

Authorization weaknesses are present within the access control mechanisms of an API. An API consumer should only have access to the resources they are authorized to access. BOLA vulnerabilities occur when an API provider does not restrict access to access to resources. BFLA vulnerabilities are present when an API provider does not restrict the actions that can be used to manipulate the resources of other users. I like to think of these in terms of fintech APIs. BOLA is the ability for UserA to see UserB's bank account balance and BFLA is the ability to for UserA to transfer funds from UserB's account back to UserA.

<br />

### Broken Object Level Authorization (BOLA)

When authorization controls are lacking or missing, UserA will be able to request UserB’s (along with many other) resources. APIs use values, such as names or numbers, to identify various objects. When we discover these object IDs, we should test to see if we can interact with the resources of other users when unauthenticated or authenticated as a different user. The first step toward exploiting BOLA is to seek out the requests that are the most likely candidates for authorization weaknesses. 



 When hunting for BOLA there are three ingredients needed for successful exploitation.

1. Resource ID: a resource identifier will be the value used to specify a unique resource. This could be as simple as a number, but will often be more complicated.
2. Requests that access resources. In order to test if you can access another user's resource, you will need to know the requests that are necessary to obtain resources that your account should not be authorized to access.
3. Missing or flawed access controls. In order to exploit this weakness, the API provider must not have access controls in place. This may seem obvious, but just because resource IDs are predictable, does not mean there is an authorization vulnerability present.

The third item on the list is something that must be tested, while the first two are things that we can seek out in API documentation and within a collection of requests. Once you have the combination of these three ingredients then you should be able to exploit BOLA and gain unauthorized access to resources. 

<br />

#### Finding Resource IDs and Requests

 You can test for authorization weaknesses by understanding how an API’s resources are structured and then attempting to access resources you shouldn’t be able to access. By detecting patterns within API paths and parameters, you might be able to predict other potential resources. The bold resource IDs in the following API requests should catch your attention:

- GET /api/resource/**1**
- GET /user/account/find?**user_id=15**
- POST /company/account/**Apple**/balance
- POST /admin/pwreset/account/**90**

In these instances, you can probably guess other potential resources, like the following, by altering the bold values:

- GET /api/resource/**3**
- GET /user/account/find?user_id=**23**
- POST /company/account/**Google**/balance
- POST /admin/pwreset/account/**111**

In these simple examples, you’ve performed an attack by merely replacing the bold items with other numbers or words. If you can successfully access the information you shouldn’t be authorized to access, you have discovered an authorization vulnerability.

Here are a few ideas for requests that could be good targets for an authorization test. 

 ![img](./assets/32.PNG)

<br /> 

#### Searching for BOLA

 First, let's think about the purpose of our target app and review the documentation. Thinking through the purpose of the app will give you a conceptual overview and help aim your sights. Ask questions like: What can you do with this app? Do you get your own profile? Can you upload files? Do you have an account balance? Is there any part of the app that has data specific to your account? Questions like these will help you search through the available requests and find a starting point for discovering requests that access resources. If we ask these questions about crAPI then you should come up with the following:

- crAPI is an application designed for new vehicle purchases. The app also allows a user to purchase items through a storefront, message other users in a public forum, and update their own user profile.
- Yes, crAPI lets users have their own profile. A user's profile contains a picture, basic user information (name, email, phone number), and a personal video.
- crAPI users have the ability to upload a profile picture and a personal video.
- Parts of the app that are specific to a user's account include
  - The user dashboard with the user's vehicle added
  - The user's profile
  - The user's past orders in the shop
  - The user's posts in the community forum

Now that we have a better idea of the purpose of the app, we should seek out requests that can provide us with relevant resources. If you remember back to the module covering Excessive Data Exposure, then there should be one request that stands out.

- **GET /identity/api/v2/videos/:id?video_id=589320.0688146055**
- **GET /community/api/v2/community/posts/w4ErxCddX4TcKXbJoBbRMf**
- **GET /identity/api/v2/vehicle/{resourceID}/location**

Note that the second request here is for public information. This request retrieves a specific request on the public crAPI forum. As far as BOLA goes, this request has the first two ingredients, but this request functions as designed by sharing public information with a group. So, no authorization is necessary for crAPI users to access this data.

 <br />

 #### Authorization Testing Strategy

When searching for authorization vulnerabilities the most effective way to find authorization weaknesses is to create two accounts and perform A-B testing. The A-B testing process consists of:

1. Create a UserA account.
2. Use the API and discover requests that involve resource IDs as UserA.
3. Document requests that include resource IDs and should require authorization.
4. Create a UserB account.
5. Obtaining a valid UserB token and attempt to access UserA's resources.

You could also do this by using UserB's resources with a UserA token. In the case of the previously mentioned requests, we should make successful requests as UserA then create a UserB account, update to the UserB token, and attempt to make the requests using UserA's resource IDs. We've already been through the account creation process several times, so I will skip ahead to a request that looks interesting.

 ![img](./assets/33.PNG)

<br />

This request looks interesting from a BOLA perspective because it is a request for a location that is based on the complex-looking vehicle ID. As UserB, I've gone through the crAPI interface and registered a vehicle. I then used the "Refresh Location" button on the web app to trigger the above request.

 ![img](./assets/34.PNG)



<br />

To make things easier for this attack capture the UserB request with Burp Suite. 

 ![img](./assets/35.PNG)

 

 <br />

 Next, perform the BOLA attack by replacing UserB's token with UserA's token and see if you can make a successful request. 

 <br />



![img](./assets/36.PNG)

<br />

Success! UserA's token is able to make a successful request and capture the GPS location of UserB's car along with their vehicleLocation ID and fullName.

In the GET request to the /community/api/v2/community/posts/recent, we discovered that the forum has excessive data exposure. One sensitive piece of data that was exposed was the vehicleID. At first glance, a developer could think that an ID of this complexity (a 32 alphanumeric token) does not require authorization security controls, something along the lines of security through obscurity. However, the complexity of this token would only help prevent or delay a brute-force attack. Leveraging the earlier discovered excessive data exposure vulnerability and combining it with this BOLA vulnerability is a real pro move. It provides a strong PoC and drives home the point of how severe these vulnerabilities really are.

 <br /><br />

---

 ### Broken Function Level Authorization (BFLA)

Where BOLA is all about accessing resources that do not belong to you, BFLA is all about performing unauthorized actions. BFLA vulnerabilities are common for requests that perform actions of other users. These requests could be lateral actions or escalated actions. Lateral actions are requests that perform actions of users that are the same role or privilege level. Escalated actions are requests that perform actions that are of an escalated role like an administrator. The main difference between hunting for BFLA is that you are looking for functional requests. This means that you will be testing for various HTTP methods, seeking out actions of other users that you should not be able to perform.

If you think of this in terms of a social media platform, an API consumer should be able to delete their own profile picture, but they should not be able to delete other users' profile pictures. The average user should be able to create or delete their own account, but they likely shouldn't be able to perform administrative actions for other user accounts. For BFLA we will be hunting for very similar requests to BOLA.

1. Resource ID: a resource identifier will be the value used to specify a unique resource. 
2. Requests that perform authorized actions. In order to test if you can access another update, delete, or otherwise alter other the resources of other users.
3. Missing or flawed access controls. In order to exploit this weakness, the API provider must not have access controls in place. 

Notice that the hunt for BFLA looks familiar, the main difference is that we will be seeking out functional requests. When we are thinking of CRUD (create, read, update, and delete), BFLA will mainly concern requests that are used to update, delete, and create resources that we should not be authorized to. For APIs that means that we should scrutinize requests that utilize POST, PUT, DELETE, and potentially GET with parameters. We will need to search through the API documentation and/or collection for requests that involve altering the resources of other users. So, if we can find requests that create, update, and delete resources specified by a resource ID then we will be on the right track. If the API you are attacking includes administrative requests or even separate admin documentation, then those will be key to see if you are able to successfully request those admin actions as a non-admin user. 

<br />

Let's return to our crAPI collection to see which requests are worth testing for BFLA. The first three requests I found in our collection were these:

- **POST /workshop/api/shop/orders/return_order?order_id=5893280.0688146055**
- **POST /community/api/v2/community/posts/w4ErxCddX4TcKXbJoBbRMf/comment** 
- **PUT /identity/api/v2/user/videos/:id**

<br />

When attacking sometimes you will need to put on your black hat thinking cap and determine what can be accomplished by successful exploitation. In the POST request to return an order, a successful exploit of this would result in having the ability to return anyone's orders. This could wreak havoc on a business that depends on sales with a low return rate. An attacker could cause a fairly severe disruption to the business. In the PUT request, there could be the potential to create, update, delete any user's videos. This would be disruptive to user accounts and cause a loss of trust in the security of the organization. Not to mention the potential social engineering implications, imagine an attacker being able to upload videos as any other user on whichever social media platform.

The purpose of the **POST /community/api/v2/community/posts/w4ErxCddX4TcKXbJoBbRMf/comment** request is to add a comment to an existing post. This will not alter the content of anyone else's post. So, while at first glance this appeared to be a potential target, this request fulfills a business purpose and does not expose the target organization to any significant risk. So, we will not dedicate any more time to testing this request. 

With BFLA we will perform a very similar test to BOLA. However, we will go one step further from A-B testing. For BFLA we will perform A-B-A testing. The reason is with BFLA there is a potential to alter another user's resources. So when performing testing there is a chance that we receive a successful response indicating that we have altered another user's resources, but to have a stronger PoC we will want to verify with the victim's account. So, we make valid requests as UserA, switch out to our UserB token, attempt to make requests altering UserA's resources, and return to UserA's account to see if we were successful.

**Please take note: When successful, BFLA attacks can alter the data of other users. This means that accounts and documents that are important to the organization you are testing could be on the line. DO NOT brute force BFLA attacks, instead, use your secondary account to safely attack your own resources. Deleting other users' resources in a production environment will likely be a violation of most rules of engagement for bug bounty programs and penetration tests.**



The two requests that look interesting for a BFLA attack include the return order request and the PUT request to update the video names. Both of these requests should require authorization to access resources that belong to the given user. Let's focus on the request to update video names. 

 ![img](./assets/37.PNG)

 

In the captured request we can see that UserA's video is specified by the resource ID "757". 

 ![img](./assets/38.PNG)

Now if we change the request so that we are using UserB's token and attempt to update the video name, we should be able to see if this request is vulnerable to a BFLA attack. 

 ![img](./assets/39.PNG)

As we can see in the attack, the API provider response is strange. Although we requested to update UserA's video, the server issued a successful response. However, the successful response indicated that UserB updated the name to the video identified as 758, UserB's video. So, this request does not seem to be vulnerable even though the response behavior was strange. Strange behavior from an app response is always worth further investigation. We should investigate other request methods that can be used for this request. 

![img](./assets/40.PNG)

Replacing PUT with DELETE illicit's a very interesting response, "This is an admin function. Try to access the admin API". In all of our testing, up to this point, we have not come across an admin API, so this is really intriguing. If we analyze the current request **DELETE /identity/api/v2/user/videos/758** there does seem like one obvious part of the path that we could alter. What if we try updating the request to DELETE /identity/api/v2/**admin**/videos/758, so that we replace "user" with "admin"?

 ![img](./assets/41.PNG)

 Success! We have now discovered an admin path and we have exploited a BFLA weakness by deleting another user's video.

Congratulations on performing successful authorization testing and exploitation. This attack is so great because the impact is often severe, while the technique is pretty straightforward. Authorization vulnerabilities continue to be the most common API vulnerabilities, so be vigilant in testing for these.  

 

 <br /><br />

----

### Improper Assets Management

In the Analyzing API Endpoints module, we created a Postman collection for crAPI. In this module, we will use this collection to test for Improper Assets Management.

Testing for Improper Assets Management is all about discovering unsupported and non-production versions of an API. Often times an API provider will update services and the newer version of the API will be available over a new path like the following:

- api.target.com/v3
- /api/v2/accounts
- /api/v3/accounts
- /v2/accounts

API versioning could also be maintained as a header:

- *Accept: version=2.0*
- *Accept api-version=3*

In addition versioning could also be set within a query parameter or request body.

- /api/accounts?ver=2

- POST /api/accounts

  {
  "ver":1.0,
  "user":"hapihacker"
  }

In these instances, earlier versions of the API may no longer be patched or updated. Since the older versions lack this support, they may expose the API to additional vulnerabilities. For example, if v3 of an API was updated to fix a vulnerability to injection attacks, then there are good odds that requests that involve v1 and v2 may still be vulnerable. 

 <br />

Non-production versions of an API include any version of the API that was not meant for end-user consumption. Non-production versions could include:

- api.test.target.com
- api.uat.target.com
- beta.api.com
- /api/private
- /api/partner
- /api/test

The discovery of non-production versions of an API might not be treated with the same security controls as the production version. Once we have discovered an unsupported version of the API, we will test for additional weaknesses. Similar to unsupported software vulnerabilities, improper assets management vulnerabilities are an indication that there is a greater chance for weaknesses to be present. Finding versions that are not included in API documentation will be at best a vulnerability for insufficient technical documentation ([CWE-1059](https://cwe.mitre.org/data/definitions/1059.html)) and at worst a gateway to more severe findings and the compromise of the provider. 

**If you haven’t done so already, build a crAPI Postman collection and obtain a valid token. See the Setup module for instructions.**

 <br />

#### Finding Improper Assets Management Vulnerabilities

You can discover mass assignment vulnerabilities by finding interesting parameters in API documentation and then adding those parameters to requests. Look for parameters involved in user account properties, critical functions, and administrative actions. Intercepting API requests and responses could also reveal parameters worthy of testing. Additionally, you can guess parameters or fuzz them in API requests that accept user input. I recommend seeking out registration processes that allow you to create and/or edit account variables. 

<br />

Now we can start by fuzzing requests across the entire API for the presence of other versions. Then we will pivot to focusing our testing based on our findings. When it comes to Improper Assets Management vulnerabilities, it is always a good idea to test from both unauthenticated and authenticated perspectives.

1. Understand the baseline versioning information of the API you are testing. Make sure to check out the path, parameters, and headers for any versioning information.
   ![img](./assets/42.PNG)

   

2. To get better results from the Postman Collection Runner, we’ll configure a test using the Collection Editor. Select the crAPI collection options, choose Edit, and select the Tests tab. Add a test that will detect when a status code 200 is returned so that anything that does not result in a 200 Success response may stick out as anomalous. You can use the following test:
   `pm.test("Status code is 200", function () { pm.response.to.have.status(200); })``![img](./assets/6.PNG)`

3. Run an unauthenticated baseline scan of the crAPI collection with the Collection Runner. Make sure that "Save Responses" is checked as seen below.
   ![img](./assets/43.PNG)

4. Review the results from your unauthenticated baseline scan to have an idea of how the API provider responds to requests using supported production versioning.
   ![img](./assets/44.PNG)

5. Next, use "Find and Replace" to turn the collection's current versions into a variable. Make sure to do this for all versions, in the case of crAPI that means **v2** and **v3**. Type the current version into "Find", update "Where" to the targeted collection, and update "Replace With" to a variable.
    ![img](./assets/45.PNG)

6. Open Postman and navigate to the environmental variables (use the eye icon located at the top right of Postman as a shortcut). *Note, we are using environmental variables so that this test can be accessed and reused for other API collections.* Add a variable named "ver" to your Postman environment and set the initial value to "v1". Now you can update to test for various versioning-related paths such as v1, v2, v3, mobile, internal, test, and uat. As you come across different API versions expand this list of variables.
   ![img](./assets/46.PNG)

7. Now that the environmental variable is set to **v1** use the collection runner again and investigate the results. You can drill down into any of the requests by clicking on them. The "check-otp" request was getting a 500 response before and now it is 404. It is worth noting the difference, but when a resource does not exist, then this would actually be expected behaviour.
   ![img](./assets/47.PNG)

   

8. If requests to paths that do not exist result in Success 200 responses, we’ll have to look out for other indicators to use to detect anomalies. Update the environmental variable to v2. Although most of the requests were already set to v2, it is worth testing because check-otp was previously set to v3.
   ![img](./assets/48.PNG)
   Once again, run the collection runner with the new value set and review the results.
   ![img](./assets/49.PNG)
   The **/v2** request for **check-otp** is now receiving the same response as the original baseline request (to /v3). Since the request for **/v1** received a *404 Not Found*, this response is really interesting. Since the request to /v2 is not a 404 and instead mirrors the response to /v3, this is a good indication that we have discovered an Improper Assets Management vulnerability. This is an interesting finding, but what is the full impact of this vulnerability?

9. Investigating the password reset request further will show that an HTTP 500 error is issued using the /v3 path because the application has a control that limits the number of times you can attempt to send the one-time passcode (OTP). Sending too many requests to **/v3** will result in a different 500 response.
   As seen from the browser:
   ![img](./assets/50.PNG)
   As seen using Postman:
   ![img](./assets/51.PNG)

   Sending the same request to /v2 also results in an HTTP 500 error, but the response is slightly larger. It may be worth viewing the two responses back in Burp Suite Comparer to see the spot differences. Notice how the response on the left has the message that indicates we guessed wrong but can try again. The request on the right indicates a new status that comes up after too many attempts have been made. 
   ![img](./assets/52.PNG)

   The /v2 password reset request responds with the body (left):
   {"message":"Invalid OTP! Please try again..","status":500}

   The /v3 password reset request responds with the body (right):
   {"message":"ERROR..","status":500}

   The impact of this vulnerability is that /v2 does not have a limitation on the number of times we can guess the OTP. With a four-digit OTP, we should be able to brute force the OTP within 10,000 requests.

10. To test this it is recommended that you use WFuzz, since Burp Suite CE will be throttled. First, make sure to issue a password reset request to your target email address. On the crAPI landing page select "Forgot Password?". Then enter a valid target email address and click "Send OTP".
    ![img](./assets/53.PNG)

11. Now an OTP is issued and we should be able to brute force the code using WFuzz. By brute forcing this request, you should see the successful code that was used to change the target's password to whatever you would like. In the attack below, I update the password to "NewPassword1". Once you receive a successful response, you should be able to login with the target's email address and the password that you choose. 
    `$ wfuzz -d '{"email":"hapihacker@email.com", "otp":"FUZZ","password":"NewPassword1"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/SecLists-master/Fuzzing/4-digits-0000-9999.txt -u http://crapi.apisec.ai/identity/api/auth/v2/check-otp --hc 500`
    ![img](./assets/54.PNG)
    Within 10,000 requests, you’ll receive a 200 response indicating your victory. Congrats, on taking this Improper Assets Management vulnerability to the next level! Since we got sidetracked with this interesting finding during unauthenticated testing, I recommend returning to the crAPI collection and performing the same tests as an authenticated user. 

 <br />

 <br />

---

### Mass Assignment Attacks

Mass Assignment vulnerabilities are present when an attacker is able to overwrite object properties that they should not be able to. A few things need to be in play for this to happen. An API must have requests that accept user input, these requests must be able to alter values not available to the user, and the API must be missing security controls that would otherwise prevent the user input from altering data objects. The classic example of a mass assignment is when an attacker is able to add parameters to the user registration process that escalate their account from a basic user to an administrator. The user registration request may contain key-values for username, email address, and password. An attacker could intercept this request and add parameters like "isadmin": "true". If the data object has a corresponding value and the API provider does not sanitize the attacker's input then there is a chance that the attacker could register their own admin account.

<br />

#### Finding Mass Assignment Vulnerabilities

One of the ways that you can discover mass assignment vulnerabilities by finding interesting parameters in API documentation and then adding those parameters to requests. Look for parameters involved in user account properties, critical functions, and administrative actions.

Additionally, make sure to use the API as it was designed so that you can study the parameters that are used by the API provider. Doing this will help you understand the names and spelling conventions of the parameters that your target uses. If you find parameters used in some requests, you may be able to leverage those in your mass assignment attacks in other requests. 

You can also test for mass assignment blind by fuzzing parameter values within requests. Mass assignment attacks like this will be necessary when your target API does not have documentation available. Essentially, you will need to capture requests that accept user input and use tools to brute force potential parameters. I recommend starting out your search for mass assignment vulnerabilities by testing your target's account registration process if there is one. Account registration is normally one of the first components of an API that accept user input. Once registration has been tested then you will need to target other requests that accept user input. In the next few minutes, we will analyze our crAPI collection to see what other requests make for interesting targets.

The challenge with mass assignment attacks is that there is very little consistency in the parameters used between API providers. That being said, if the API provider has some method for, say, designating accounts as administrators, they may also have some convention for creating or updating variables to make a user an administrator. Fuzzing can speed up your search for mass assignment vulnerabilities, but unless you understand your target’s variables, this technique can be a shot in the dark. Let's target crAPI for mass assignment vulnerabilities

<br />

#### Testing Account Registration for Mass Assignment

Let's intercept the account registration request for crAPI.

1. While using a browser, submit data for creating a new account. Enter your email and password into the form. Set FoxyProxy to proxy traffic to Burp Suite.
   ![img](./assets/55.PNG)

2. Submit the form to create an account and make sure the request was intercepted with Burp Suite. 
   ![img](./assets/56.PNG)

3. Send the intercepted request to Repeater. Before submitting any attacks, send a successful request to have a baseline understanding of how the API responds to an expected request. 
   ![img](./assets/57.PNG)

   

4. Next, test the registration process for mass assignment. The simplest form of this attack is to upgrade an account to an administrator role by adding a variable that the API provider likely uses to identify admins. If you have access to admin documentation then there is a good chance that the parameters will be included in the registration requests. You can then use the discovered parameters to see if the API has any security controls preventing you from escalating a user account to an admin account. If you do not have admin docus, then you can do a simple test by including other key-values to the JSON POST body, such as:
   "isadmin": true,
   "isadmin":"true",
   "admin": 1,
   "admin": true, 
   Any of these may cause the API to respond in a unique way indicating success or failure.
   ![img](./assets/58.PNG)

   

5. Once you attempt to a mass assignment attack on your target, you will need to analyze how the API responds. In the case of crAPI, there is no unique response when additional parameters are added to the request. There are no indications that the user account was changed in any way. 

6. Another way to test more options would be to send this over to Intruder and place attack positions around the new key and value that you want to test. In our case, this would be **isadmin** and **true**. Set the attack type to cluster bomb and add payloads for positions 1 and 2. Run this and review the results for anything unique. 
   ![img](./assets/59.PNG)
   In the case of crAPI, the registration process does not respond in any way that indicates it is vulnerable to mass assignment. There are several tools out there that can fuzz for mass assignment vulnerabilities, but since we are using Burp Suite it is worth checking out Param Miner.

<br />

#### Fuzzing for Mass Assignment with Param Miner

1. Make sure you have Param Miner installed as an extension to Burp Suite CE.
   ![img](./assets/60.PNG)
2. Right-click on a request that you would like to mine for parameters. Select Extensions > Param Miner > Guess params > Guess JSON parameter. Feel free to experiment with the other options!
   ![img](./assets/61.PNG)
3. Set the Param Miner options that you would like and click OK when you are done. Check out the unofficial documentation for an additional explanation of the options (https://github.com/nikitastupin/param-miner-doc).
   ![img](./assets/62.PNG)
4. Navigate back to Extender-Extensions and select Parm Miner. Next, select the Output tab and wait for results to populate this area.
   ![img](./assets/63.PNG)
5. If any new parameters are detected, insert them back into the original request and fuzz for results.

<br />

#### Other Mass Assignment Vectors

Mass assignment attacks go beyond making attempts to become an administrator. You could also use mass assignment to gain unauthorized access to other organizations, for instance. If your user objects include an organizational group that allows access to company secrets or other sensitive information, you can attempt to gain access to that group. In this example, we’ve added an "org" variable to our request and turned its value into an attack position we could then fuzz in Burp Suite:

POST /api/v1/register

--snip--

{

"username":"hAPI_hacker",

"email":"hapi@hacker.com",

"org": "§CompanyA§",

"password":"Password1!"

}

If you can assign yourself to other organizations, you will likely be able to gain unauthorized access to the other group’s resources. To perform such an attack, you’ll need to know the names or IDs used to identify the companies in requests. If the "org" value was a number, you could brute-force its value, like when testing for BOLA, to see how the API responds.

Do not limit your search for mass assignment vulnerabilities to the account registration process. Other API functions are capable of being vulnerable. Test other endpoints used for updating accounts, updating group information, user profiles, company profiles, and any other requests where you may be able to assign yourself additional access.

<br />

#### Hunting for Mass Assignment

As with many other API attacks, we will start hunting for this vulnerability by analyzing the target API collection. Remember, mass assignment is all about binding user input to data objects. So, when you analyze a collection that you are targeting you will need to find requests that:

- Accept user input
- Have the potential to modify objects

![img](./assets/64.PNG)

After reviewing the crAPI collection, two requests stick out to me as interesting. 

**POST /workshop/api/merchant/contact_mechanic**

**POST /workshop/api/shop/orders**

Both of these requests involve user input and have the potential to modify objects.

Similar to authorization testing, I recommend creating a new collection just for mass assignment testing. This way we can test out interesting requests without damaging the original collection. Make sure when duplicating requests to update unresolved variables. 

![img](./assets/65.PNG)

 You can update unresolved variables at the collection level or by selecting "Add new variable". In this case, add the base URL variable value and select the collection that this is relevant to.

![img](./assets/66.PNG)

Get a better understanding of the requests that you've targeted. Once again, use the API as it was intended. Sometimes the scope of an API security test can be so large that it helps to be reminded of the purpose of a single request. If it is not clear from the perspective of the API collection, then it can be helpful to return to the web app.

![img](./assets/67.PNG)

When we return to the web app and intercept the requests involved with the workshop, we see that the **POST /workshop/api/shop/orders** request is involved in the process used for purchasing products from the crAPI store. This request is even more interesting now that we know what an important role it plays for the target organization.  

![img](./assets/68.PNG)

Again, we can attempt to guess key values to use in this attack or use Param Miner. Try this out. Unfortunately, neither attempts come up interesting. Although we do not have documentation for crAPI, we can learn more about "product_id" in other requests. Another request that is involved in the workshop store is **GET /workshop/api/shop/products**.

![img](./assets/69.PNG)

Checking this request out reveals the full catalog of store products along with the product id, name, price, and image URL. If we could submit user data to products there would be a great opportunity to leverage a mass assignment attack. If we were able to submit data here we would be able to create our own products with our own prices. However, this request uses the GET method and is only for requesting data not altering it. Well, how do the crAPI administrators manage the products page? Perhaps they use PUT or POST to submit products to this endpoint and it wouldn't be the first time that we have discovered a BFLA vulnerability with this target. Always try to leverage vulnerability findings in other requests when testing a target organization. Chances are if the secure development practices of an organization fall short in one aspect of the application, they likely fall short in other areas.

![img](./assets/70.PNG)

Sending a POST request to /workshop/api/shop/products yields very interesting results! The API responds with suggested fields for a POST request, which is an indication that this request is vulnerable to BFLA. If we are able to submit requests to alter or create store products, then we will be able to confirm that it is also vulnerable to Mass Assignment.

![img](./assets/71.PNG)

The request to add our own product is successful! The API responds with Status 200 and the information that was submitted. We can also navigate to the web app to verify our results.

![img](./assets/72.PNG)

So, we can create our own product items, but how can we exploit this vulnerability to the next level? What if we were to make the price a negative number?![img](./assets/73.PNG)

<br />

The API responds back with a new product that has a negative value for the price. If we go back and purchase this item now, we should see a pretty great proof of concept for this exploit in the form of a new account balance.

![img](./assets/74.PNG)

 

Congratulations on exploiting a mass assignment vulnerability! This one took experimentation, pivoting, and combining weaknesses discovered in other areas of the API. This level of analysis and effort to exploit an API vulnerability is what will help you level up your API hacking skills.

<br />

<br />

---

### Reference

- https://university.apisec.ai/products/api-penetration-testing

 



 

 

 

 

 
