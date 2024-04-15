# API Penetration Testing



## Table of Contents

- [Passive API recon](#)
- [Active API recon]
- [Endpoint Analysis: Reverse Engineering an API]
  - [1. Building a Collection in Postman with postman proxy]
  - [2. Automatic Documentation with mitmweb ]
- [API Authentication Attacks]
  - [1. Password Brute-Force Attacks]
  - [2. Password Spraying]
  - [3. Token Analysis]
  - [4. JWT Attacks]
  - [Automating JWT attacks with JWT_Tool]
- [API Authorization Attacks]
  - [Broken Object Level Authorization (BOLA)]



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





### 2. Shodan

- hostname:"targetname.com"
- "content-type: application/json"
- "content-type: application/xml"
- "wp-json"



### 3. **The Wayback Machine**



---



## Active API recon

### 1. nmap

```bash
nmap -sC -sV 127.0.0.1
nmap -p- 127.0.0.1
nmap -sV --script=http-enum <target> -p 80,443,8000,8080
```



### 2. amass

```bash
amass enum -active -d target.com | grep "api"
 amass enum -active -brute -w /usr/share/wordlists/API_superlist -d [target domain] -dir [directory name]  
```



### 3. Directory bruteforce

```bash
gobuster
dirb
```



### 4. **Kiterunner**

Kiterunner is an excellent tool that was developed and released by Assetnote. Kiterunner is currently the best tool available for discovering API endpoints and resources. While directory brute force tools like Gobuster/Dirbuster/ work to discover URL paths, it typically relies on standard HTTP GET requests. Kiterunner will not only use all HTTP request methods common with APIs (GET, POST, PUT, and DELETE) but also mimic common API path structures. In other words, instead of requesting GET /api/v1/user/create, Kiterunner will try POST /api/v1/user/create, mimicking a more realistic request.

You can perform a quick scan of your target’s URL or IP address like this:

```bash
$ kr scan HTTP://127.0.0.1 -w ~/api/wordlists/data/kiterunner/routes-large.kite
$ kr brute <target> -w ~/api/wordlists/data/automated/nameofwordlist.txt
```



---

## Endpoint Analysis

### Reverse Engineering an API



### 1. Building a Collection in Postman with postman proxy

In the instance where there is no documentation and no specification file, you will have to reverse-engineer the API based on your interactions with it. Mapping an API with several endpoints and a few methods can quickly grow into quite a large attack surface. To manage this process, build the requests under a collection in order to thoroughly hack the API. Postman can help you keep track of all of these requests. There are two ways to manually reverse engineer an API with Postman. One way is by constructing each request. While this can be a bit cumbersome, it will allow you to add the precise requests you care about. The other way is to proxy web traffic through Postman, and then use it to capture a stream of requests. This process makes it much easier to construct requests within Postman, but you’ll have to remove or ignore unrelated requests. Later in this module, we'll review a great way to automatically document APIs with mitmproxy2swagger.

First, let's launch Postman.

$ postman

Next, create a Workspace to save your collections in. For this course, we will use the ACE workspace. 

To build your own collection in Postman with the Proxy, use the Capture Requests button, found at the bottom right of the Postman window. 

![img](./assets/1.PNG)

In the Capture requests window, select Enable proxy. The port should match with the number that is set up in FoxyProxy (5555). Next, enable the Postman Proxy, add your target URL to the "URL must contain" field, and click the Start Capture button.

![img](./assets/2.PNG)

Open up your web browser, navigate to crAPI's landing page, and use FoxyProxy to enable the Postman option. Now you can meticulously use the web app as intended. Meticulous, because you want to capture every single bit of functionality available within the application. This means using all of the features of the target. Click on links, register for an account, sign in to the account, visit your profile, post comments in a forum, etc. Essentially click all the things, update information where you can, and explore the web app in its entirety. How thorough you use the web app will have a domino effect on what endpoints and requests you will later test. For example, if you were to perform the various actions of the web app, but forgot to test the community endpoints then you will have a blindspot in the API attack surface. 

![img](./assets/3.PNG)

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

 

Once you have captured all of the features you can find with manual exploration then you will want to Stop the Proxy. Next, it is time to build the crAPI collection. First, create a new collection by selecting the new button (top left side of Postman) and then choose Collection.

![img](./assets/5.PNG)

Go ahead and rename the collection to **crAPI Proxy Collection**. Navigate back to the Proxy debug session and open up the Requests tab.

![img](./assets/6.PNG)

Select all of the requests that you captured and use the "add to Collection" link highlighted above. Select the crAPI Proxy Collection and organize the requests by Endpoints. With all of the captured requests added to the crAPI Proxy Collection, you can organize the collection by renaming all of the requests and grouping similar requests into folders. Before you get too far into this exercise, I would recommend checking out the automated documentation instructions below. 



## 2. Automatic Documentation with mitmweb 

First, we will begin by proxying all web application traffic using mitmweb.

Simply use a terminal and run:

```bash
$ mitmweb
```





![img](./assets/7.png)

This will create a proxy listener using port 8080. You can then open a browser and use FoxyProxy to proxy your browser to port 8080 using our Burp Suite option.

![img](./assets/8.png)

Once the proxy is set up, you can once again use the target web application as it was intended.

*Note: if you are reverse engineering crapi.apisec.ai you may run into certificate issues if you have not yet added the mitmweb cert. Please return back to Kali Linux and More MITMweb Certificate Setup for instructions.*

Every request that is created from your actions will be captured by the mitmweb proxy. You can see the captured traffic by using a browser to visit the mitmweb web server located at http://127.0.0.1:8081.

![img](./assets/9.png)

 

Continue to explore the target web application until there is nothing left to do. Once you have exhausted what can be done with your target web app, return to the mitmweb web server and click **File > Save** to save the captured requests.

![img](./assets/10.png)

Selecting **Save** will create a file called flows. We can use the "flows" file to create our own API documentation. Using a great tool called mitmproxy2swagger, we will be able to transform our captured traffic into an Open API 3.0 YAML file that can be viewed in a browser and imported as a collection into Postman.

First, run the following:

```bash
$sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://crapi.apisec.ai -f flow
```



![img](./assets/11.png)

After running this you will need to edit the spec.yml file to see if mitmproxy2swagger has ignored too many endpoints. Checking out spec.yml reveals that several endpoints were ignored and the title of the file can be updated. You can use Nano or another tool like Sublime to edit the spec.yml.

![img](./assets/12.PNG)

Update the YAML file so that "ignore:" is removed from the endpoints that you want to include. If you're are using Sublime, you can simply select all of the endpoints that you want to edit (hold CTRL while selecting) and then use (CTRL+Shift+L) to perform a simultaneous multi-line edit.
![img](./assets/13.PNG)

 

Make sure to **only remove "ignore:"**. Removing spacing or the "-" can result in the script failing to work. 

![img](./assets/14.PNG)

 

Note that the "title" has been updated to "crAPI Swagger" and that the endpoints no longer contain "ignore:". Once your docs look similar to the image above, make sure to run the script once more. This second run will correct the format and spacing. This time around you can add the "--examples" flag to enhance your API documentation.

```bash
$sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://crapi.apisec.ai -f flow --examples
```





![img](./assets/15.png)

After running mitmproxy2swagger successfully a second time through, your reverse-engineered documentation should be ready. You can validate the documentation by visiting https://editor.swagger.io/ and by importing your spec file into the Swagger Editor. Use **File>Import file** and select your spec.yml file. If everything has gone as planned then you should see something like the image below. This is a pretty good indication of success, but to be sure we can also import this file as a Postman Collection that way we can prepare to attack the target API.

![img](./assets/16.png)

 To import this file as a collection we will need to open Postman. At the top left of your Postman Workspace, you can click the "Import" button. Next, select the spec.yml file and import the collection.

![img](./assets/17.png)

Once you import the file you should see a relatively straightforward API collection that can be used to analyze the target API and exploit with future attacks.

![img](./assets/18.png)

With a collection prepared, you should now be ready to use the target API as it was designed. This will enable you to see the various endpoints and understand what is required to make successful requests. In the next module, we will begin working with the API and learn to analyze various requests and responses. 



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



---

### 2. Password Spraying

Many security controls could prevent you from successfully brute-forcing an API’s authentication. A technique called password spraying can evade many of these controls by combining a long list of users with a short list of targeted passwords. Let’s say you know that an API authentication process has a lockout policy in place and will only allow 10 login attempts. You could craft a list of the nine most likely passwords (one less password than the limit) and use these to attempt to log in to many user accounts.

When you’re password spraying, large and outdated wordlists like rockyou.txt won’t work. There are way too many unlikely passwords in such a file to have any success. Instead, craft a short list of likely passwords, taking into account the constraints of the API provider’s password policy, which you can discover during reconnaissance. 

Most password policies likely require a minimum character length, upper- and lowercase letters, and perhaps a number or special character. Use passwords that are simple enough to guess but complex enough to meet basic password requirements (generally a minimum of eight characters, a symbol, upper- and lowercase letters, and a number). The first type includes obvious passwords like QWER!@#$, Password1!, and the formula Season+Year+Symbol (such as Winter2021!, Spring2021?, Fall2021!, and Autumn2021?). 

The second type includes more advanced passwords that relate directly to the target, often including a capitalized letter, a number, a detail about the organization, and a symbol. Here is a short password-spraying list I might generate if I were attacking an endpoint for Twitter employees: Summer2022! Spring2022! QWER!@#$ March212006! July152006! Twitter@2022 JPD1976! [Dorsey@2022](mailto:Dorsey@2021) .

The real key to password spraying is to maximize your user list. The more usernames you include, the higher your odds of compromising a user account with a bad password. Build a user list during your reconnaissance efforts or by discovering excessive data exposure vulnerabilities.



**to extract mails from response**

```bash
$grep -oe "[a-zA-Z0-9._]\+@[a-zA-Z]\+.[a-zA-Z]\+" response.json | sort -u
```





---

### 3. Token Analysis

When implemented correctly, tokens can be an excellent tool that can be used to authenticate and authorize users. However, if anything goes wrong when generating, processing, or handling tokens, they can become our keys to the kingdom.

In this section, we will take a look at the process that can be used with Burp Suite to analyze tokens. Using this process can help you identify predictable tokens and aid in token forgery attacks. To analyze tokens we will take our crAPI API authentication request and proxy it over to Burp Suite.

![img](./assets/19.PNG)

Next, you will need to right-click on the request and forward it over to Sequencer. In Sequencer, we will be able to have Burp Suite send thousands of requests to the provider and perform an analysis of the tokens received in response. This analysis could demonstrate that a weak token creation process is in use.

Navigate to the Sequencer tab and select the request that you forwarded. Here we can use the Live Capture to interact with the target and get live tokens back in a response to be analyzed. To make this process work, you will need to define the custom location of the token within the response. Select the Configure button to the right of Custom Location. Highlight the token found within quotations and click OK.

![img](./assets/20.PNG)



Once the token has been defined then you can Start live capture. At this point, you can either wait for the capture to process thousands of requests or use the Analyze now button to see results sooner.

![img](./assets/21.PNG)



Using Sequencer against crAPI shows that the tokens generated seem to have enough randomness and complexity to not be predictable. Just because your target sends you a seemingly complex token, does not mean that it is safe from token forgery. Sequencer is great at showing that some complex tokens are actually very predictable. If an API provider is generating tokens sequentially then even if the token were 20 plus characters long, it could be the case that many of the characters in the token do not actually change. Making it easy to predict and create our own valid tokens.

To see what an analysis of a poor token generation process looks like perform an analysis of the "bad tokens" located on the Hacking APIs Github repository (https://raw.githubusercontent.com/hAPI-hacker/Hacking-APIs/main/bad_tokens). This time around we will use the Manual load option, to provide our own set of bad tokens. 

![img](./assets/22.PNG)

If you use the Analyze Now button and let Sequencer run its analysis. Check out the Character-level analysis which reveals that the 12 alpha-numeric token uses the same characters for the first 8 positions. The final three characters of these tokens have some variation. Taking note of the final three characters of these tokens you can notice that the possibilities consist of two lower-case letters followed by a number (aa#). With this information, you could brute-force all of the possibilities in under 7,000 requests. Then you can take these tokens and make requests to an endpoint like */identity/api/v2/user/dashboard.* Based on the results of your requests, search through the usernames and emails to find users that you would like to attack.



---

### 4. JWT Attacks

JSON Web Tokens (JWTs) are one of the most prevalent API token types because they operate across a wide variety of programming languages, including Python, Java, Node.js, and Ruby. These tokens are susceptible to all sorts of misconfiguration mistakes that can leave the tokens vulnerable to several additional attacks. These attacks could provide you with sensitive information, grant you basic unauthorized access, or even administrative access to an API. This module will guide you through a few attacks you can use to test and break poorly implemented JWTs. 

JWTs consist of three parts, all of which are base64 encoded and separated by periods: the header, payload, and signature. JWT.io is a free web JWT debugger that you can use to check out these tokens. You can spot a JWT because they consist of three periods and begin with "ey". They begin with "ey" because that is what happens when you base64 encode a curly bracket followed by a quote, which is the way that a decoded JWT always begins. 



You could use this token in requests to gain access to the API as the user specified in the payload. More commonly, though, you’ll obtain a JWT by authenticating to an API and the provider will respond with a JWT. In order to obtain a JWT from crAPI, we will need to leverage our authentication request.

![img](./assets/23.PNG)

The token we receive back from crAPI doesn't necessarily say "JWT: anywhere, but we can easily spot the "ey" and three segments separated by periods. The first step to attacking a JWT is to decode and analyze it. If we take this token and add it to the JWT debugger this is what we see.

![img](./assets/24.PNG)

In this example, we can see the algorithm is set to HS512, the email of our account, iat, exp, and the current signature is invalid. If we were able to compromise the signature secret then we should be able to sign our own JWT and potentially gain access to any valid user's account. Next, we will learn how to use automated tooling to help us with various JWT attacks.



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



In the case of crAPI we will run:

```bash
$jwt_tool -t http://127.0.0.1:8888/identity/api/v2/user/dashboard -rh "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYWFhQGVtYWlsLmNvbSIsImlhdCI6MTY1ODUwNjQ0NiwiZXhwIjoxNjU4NTkyODQ2fQ.BLMqSjLZQ9P2cxcUP5UCAmFKVMjxhlB4uVeIu2__6zoJCJoFnDqTqKxGfrMcq1lMW97HxBVDnYNC7eC-pl0XYQ" -M pb
```



 ![img](./assets/26.PNG)

During this scan for common misconfiguration, JWT_Tool tested the various claims found within the JWT (sub, iat, exp)



#### The None Attack

If you ever come across a JWT using "none" as its algorithm, you’ve found an easy win. After decoding the token, you should be able to clearly see the header, payload, and signature. From here, you can alter the information contained in the payload to be whatever you’d like. For example, you could change the username to something likely used by the provider’s admin account (like root, admin, administrator, test, or adm), as shown here: { "username": "root", "iat": 1516239022 } Once you’ve edited the payload, use Burp Suite’s Decoder to encode the payload with base64; then insert it into the JWT. Importantly, since the algorithm is set to "none", any signature that was present can be removed. In other words, you can remove everything following the third period in the JWT. Send the JWT to the provider in a request and check whether you’ve gained unauthorized access to the API.

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



#### JWT Crack Attack

The JWT Crack attack attempts to crack the secret used for the JWT signature hash, giving us full control over the process of creating our own valid JWTs. Hash-cracking attacks like this take place offline and do not interact with the provider. Therefore, we do not need to worry about causing havoc by sending millions of requests to an API provider. You can use JWT_Tool or a tool like Hashcat to crack JWT secrets. You’ll feed your hash cracker a list of words. The hash cracker will then hash those words and compare the values to the original hashed signature to determine if one of those words was used as the hash secret. If you’re performing a long-term brute-force attack of every character possibility, you may want to use the dedicated GPUs that power Hashcat instead of JWT_Tool. That being said, JWT_Tool can still test 12 million passwords in under a minute. First, let's use Crunch, a password-generating tool, to create a list of all possible character combinations to use against crAPI.

```bash
$crunch 5 5 -o crAPIpw.txt
```



![img](./assets/27.PNG)



We can use this password file that contains all possible character combinations created for 5 character passwords against our crAPI token. To perform a JWT Crack attack using JWT_Tool, use the following command: 

```bash
$ jwt_tool TOKEN -C -d wordlist.txt
```



 The -C option indicates that you’ll be conducting a hash crack attack, and the -d option specifies the dictionary or wordlist you’ll be using against the hash. JWT_Tool will either return “CORRECT key!” for each value in the dictionary or indicate an unsuccessful attempt with “key not found in dictionary.”

![img](./assets/28.PNG)



Now that we have the correct secret key that is used to sign crAPI's tokens, we should be able can generate our own trusted tokens. To test out our new abilities, you can either create a second user account in crAPI or use an email that you have already discovered. I have created an account named "superadmin".

![img](./assets/29.PNG)



You can add your user token to the JWT debugger, add the newly discovered secret, and update the "sub" claim to any email that has registered to crAPI.

![img](./assets/30.PNG)



Use the token that you generated in the debugger and add it to your Postman Collection. Make a request to an endpoint that will prove your access such as GET /identity/api/v2/user/dashboard. 

![img](./assets/31.PNG)





---



## API Authorization Attacks

An API’s authentication process is meant to validate that users are who they claim to be. An API's authorization is meant to allow users to access the data they are permitted to access. In other words, UserA should only be able to access UserA's resources and UserA should not be able to access UserB's resources. API providers have been pretty good about requiring authentication when necessary, but there has been a tendency to overlook controls beyond the hurdle of authentication. Authorization vulnerabilities are so common for APIs that the OWASP security project included two authorization vulnerabilities on its top ten list, `Broken Object Level Authorization (BOLA)` and `Broken Function Level Authorization (BFLA)`.

RESTful APIs are stateless, so when a consumer authenticates to these APIs, no session is created between the client and server. Instead, the API consumer must prove their identity within every request sent to the API provider’s web server. 

 

Authorization weaknesses are present within the access control mechanisms of an API. An API consumer should only have access to the resources they are authorized to access. BOLA vulnerabilities occur when an API provider does not restrict access to access to resources. BFLA vulnerabilities are present when an API provider does not restrict the actions that can be used to manipulate the resources of other users. I like to think of these in terms of fintech APIs. BOLA is the ability for UserA to see UserB's bank account balance and BFLA is the ability to for UserA to transfer funds from UserB's account back to UserA.



### Broken Object Level Authorization (BOLA)

When authorization controls are lacking or missing, UserA will be able to request UserB’s (along with many other) resources. APIs use values, such as names or numbers, to identify various objects. When we discover these object IDs, we should test to see if we can interact with the resources of other users when unauthenticated or authenticated as a different user. The first step toward exploiting BOLA is to seek out the requests that are the most likely candidates for authorization weaknesses. 



 When hunting for BOLA there are three ingredients needed for successful exploitation.

1. Resource ID: a resource identifier will be the value used to specify a unique resource. This could be as simple as a number, but will often be more complicated.
2. Requests that access resources. In order to test if you can access another user's resource, you will need to know the requests that are necessary to obtain resources that your account should not be authorized to access.
3. Missing or flawed access controls. In order to exploit this weakness, the API provider must not have access controls in place. This may seem obvious, but just because resource IDs are predictable, does not mean there is an authorization vulnerability present.

The third item on the list is something that must be tested, while the first two are things that we can seek out in API documentation and within a collection of requests. Once you have the combination of these three ingredients then you should be able to exploit BOLA and gain unauthorized access to resources. 

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

 

 #### Authorization Testing Strategy

When searching for authorization vulnerabilities the most effective way to find authorization weaknesses is to create two accounts and perform A-B testing. The A-B testing process consists of:

1. Create a UserA account.
2. Use the API and discover requests that involve resource IDs as UserA.
3. Document requests that include resource IDs and should require authorization.
4. Create a UserB account.
5. Obtaining a valid UserB token and attempt to access UserA's resources.

You could also do this by using UserB's resources with a UserA token. In the case of the previously mentioned requests, we should make successful requests as UserA then create a UserB account, update to the UserB token, and attempt to make the requests using UserA's resource IDs. We've already been through the account creation process several times, so I will skip ahead to a request that looks interesting.

 ![img](./assets/33.PNG)



This request looks interesting from a BOLA perspective because it is a request for a location that is based on the complex-looking vehicle ID. As UserB, I've gone through the crAPI interface and registered a vehicle. I then used the "Refresh Location" button on the web app to trigger the above request.

 ![img](./assets/34.PNG)



To make things easier for this attack capture the UserB request with Burp Suite. 

 ![img](./assets/35.PNG)

 

 

 Next, perform the BOLA attack by replacing UserB's token with UserA's token and see if you can make a successful request. 

 



![img](./assets/36.png)

Success! UserA's token is able to make a successful request and capture the GPS location of UserB's car along with their vehicleLocation ID and fullName.

In the GET request to the /community/api/v2/community/posts/recent, we discovered that the forum has excessive data exposure. One sensitive piece of data that was exposed was the vehicleID. At first glance, a developer could think that an ID of this complexity (a 32 alphanumeric token) does not require authorization security controls, something along the lines of security through obscurity. However, the complexity of this token would only help prevent or delay a brute-force attack. Leveraging the earlier discovered excessive data exposure vulnerability and combining it with this BOLA vulnerability is a real pro move. It provides a strong PoC and drives home the point of how severe these vulnerabilities really are.

 

 

 

 

 

 

 

##  

 

 

 

 

 

 

 

 

 
