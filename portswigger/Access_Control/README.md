
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





