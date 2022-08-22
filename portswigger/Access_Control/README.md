
## Access control vulnerabilities



### [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

Goal : delete the user `carlos` by accessing the admin panel

- go to `/robots.txt` , you will find the admin panel path

- ```
  User-agent: *
  Disallow: /administrator-panel
  ```

- go to `/administrator-panel` and delete `carlos`



------



### [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

Goal : delete the user `carlos` by accessing the admin panel

- view the page source , you will find this javascript code 

````javascript
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-h49xc1');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
````

- go to the admin panel `/admin-h49xc1` and delete `carlos`

 

------


### [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

Goal : delete the user `carlos` by accessing the admin panel

- go to `/login` , login with your credentials `wiener : peter`
- modify `Admin` in the cookies from `false` to `true`
- go to `/admin`  and delete `carlos`





------



### [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

Goal : delete the user `carlos` by accessing the admin panel

- go to `/login` , login with your credentials `wiener : peter`
- update your email , you will find that your account info are exist in the response

![](./access-control_img/1_1.png)



- send the request to burp repeater and add `"roleid" : 2` to the request

![](./access-control_img/1_2.png)



- go to `/admin`  and delete `carlos`



------



