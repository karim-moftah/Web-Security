## Proxies



- A web proxy/interception proxy is a tool that is used to capture, analyze and modify requests and responses exchanged between an HTTP client
  and a server.
- By intercepting HTTP/HTTPS requests and responses, a pentester can analyze and study the behaviour and functionality of a web application.
- Proxies are a fundamental component of web application penetration tests and will become one of your most trusted allies when assessing and testing web apps.
- The most popular and widely utilized web proxies used today are:
  - Burp Suite
  - OWASP ZAP





### Web Proxy vs Web Proxy Server

- It is important to distinguish between web proxies and proxy servers.
- A web proxy is used to intercept, analyze or modify HTTP/HTTPS requests sent between a client and server (Burp Suite or OWASP ZAP).
- A web proxy server is used to proxy internet traffic, filter specific traffic and optimize bandwidth (Squid Proxy).
- The next two illustrations will clarify this distinction.



### Web Proxy

![](./assets/1.png)









### Web Proxy Server

![](./assets/2.png)

















## Burpsite



**increase number of concurrent requests or delay between requests if there is a waf or for any reason**

Dashboard > setting > Resourse pool 



![](./assets/3.png)









**Add target and its subdomains to scope** 

1- dashboard > enable passive crawler

2- target > scope setting > check `use advanced scope control` > add

Host or ip range:

```bash
.*\.domian\.com$
```

![](./assets/4.png)









