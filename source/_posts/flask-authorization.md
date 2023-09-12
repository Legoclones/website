---
title: Demystifying Flask's request.authorization
date: 2023-09-11 00:00:00
tags: 
- security-research
- web
---

# Demystifying Flask's `request.authorization`
While doing HITB's Secconf Attack/Defense CTF, there was one web service that a teammate and I came across that used Python's Flask webserver. Authentication was implemented using `request.authorization` and `Authorization: Bearer ...` headers. We started fuzzing the header to see if we could get any weird behavior, and stumbled upon a 500 Internal Server Error being thrown whenever there was an equals sign (`=`) in the middle of one of these tokens. 

After the CTF, I did some digging into this weird behavior to see why that would break it. It turns out [Flask changed the way it handles `Authorization` headers](https://flask.palletsprojects.com/en/2.3.x/api/#flask.Request.authorization) in version 2.3, and the new handling isn't super clearly documented. Also, all relevant questions about `request.authorization` that I could find on the Internet referred to the old handling and not the new way. In this blog post, I will attempt to clearly define the behavior of Flask when it comes to `Authorization` headers, and define edge cases and weird behavior. This way, security researchers, CTFers, and developers can understand how to properly deal with `Authorization` headers and avoid unintended behavior.

## Old `request.authorization`
Previously, Flask only supported Basic Authentication from the `Authorization` header, where it parsed the base64-encoded value, and returned a Python Dictionary like `{"username":"value","password":"value"}`. However, using `Authorization: Bearer <token>` has become a lot more popular in recent years, and so to ensure developers don't have to parse those tokens themselves, Flask pushed out an update so that `request.authorization` returns a [`werkzeug.datastructures.Authorization` object](https://werkzeug.palletsprojects.com/en/2.3.x/datastructures/#werkzeug.datastructures.Authorization).

## Parsing the `Authorization` Header
When you call `request.authorization`, Python will inevitably call the `from_header()` function of the Authorization class with the sole parameter being `request.headers['Authorization']`. If the `Authorization` header is not defined in the HTTP request, this will return `None`. 

The header is parsed into 2 parts - the scheme, and the "rest"; these 2 parts are separated by the first space (if multiple spaces are in the header, the scheme is everything before the first space, and the "rest" is everything else). If `scheme == 'basic'`, then the "rest" is based64-decoded, with the username being everything before the colon (`:`) and the password being everything afterwards. 

If the scheme is not `'basic'`, it's ignored. If "rest" has an equals sign that's NOT at the end, it's treated as parameters; otherwise, it's treated as a token (no Authorization object can have both a token and parameters defined). Parameters are parsed using `key=value, key2=value2`, and the token isn't parsed as anything. The parsing seems fairly simple, but the way it's accessed is kind of weird and we run into some odd edge cases (which I'll go over later). 

A review:
- If the scheme is `basic` (case-insensitive), then 2 parameters (`username` and `password`) are extracted from the base64-encoded, colon-separated remainder
- If an equals sign is present in the middle of the "rest", then the entire "rest" is parsed as parameters using the [`parse_dict_header()` function](https://github.com/pallets/werkzeug/blob/01fa8ee1bb24d1a30c2acb172d355fcd9933f9d4/src/werkzeug/http.py#L327)
    - *Note that the `parse_dict_header()` has interesting functionality itself, such as support for various encoding techniques*
- Otherwise, the entire "rest" is processed as a token

## Accessing `request.authorization` Information
Let's use the header `Authorization: Bearer test`

* `request.authorization == 'Bearer test'`
* `request.authorization.parameters == {}`
* `request.authorization.token == 'test'`

Our second example is `Authorization: Bearer key=value`

* `request.authorization == 'Bearer key=value'`
* `request.authorization.parameters == {"key": "value"}`
* `request.authorization.token == None`

Our third example is `Authorization: Bearer dXNlcm5hbWU6cGFzc3dvcmQ=`

* `request.authorization == 'Bearer dXNlcm5hbWU6cGFzc3dvcmQ='`
* `request.authorization.parameters == {"username": "username", "password": "password"}`
* `request.authorization.token == None`

## Interesting Edge Cases and Behavior
Here are some examples where the parsing is somewhat interesting and, depending on a setup, can lead to unintended behavior. 

* `Authorization: test test` --> `request.authorization == 'Test test'` (*notice the forced capitalization*)
* `Authorization: bAsIc dXNlcm5hbWU6cGFzc3dvcmQ=` --> `request.authorization.parameters  == {"username": "username", "password": "password"}` (*case-insensitive scheme*)
* `Authorization: asdf token` --> `request.authorization.token == 'token'` (*all non-basic schemes are ignored*)
* `Authorization: Bearer a~!@#$%^&*()_+b` --> `request.authorization.token == 'a~!@#$%^&*()_+b'` (*all non-equals sign symbols are accepted*)
* `Authorization: Bearer a~!@#$%^&*(=)_+b` --> `request.authorization.token == None` (*Bearer tokens with an equals sign are not processed as tokens*)
* `Authorization: Bearer a~!@#$%^&*()_+b=` --> `request.authorization.token == 'a~!@#$%^&*()_+b='` (*Bearer tokens with an equals sign at the end are processed as tokens*)
* `Authorization: Bearer username=username,password=password` --> `request.authorization.parameters  == {"username": "username", "password": "password"}` (*using parameters will give the same result as the Basic scheme*)
* `Authorization: Bearer key1=test,key2`
    * `request.authorization.parameters == {"key1":"test", "key2":None}`
    * `request.authorization["key1"] == "test"`
    * `request.authorization["key2"] == None`
    * `request.authorization.key1 == "test"`
    * `request.authorization.key2 == None`
    * (*parameters can be accessed through the `parameter` attribute, using dot notation, or using index notation*)
    * (*if a key has no value, it's set to None by default*)
* `Authorization: Bearer token=a`
    * `request.authorization.parameters == {"token":"a"}`
    * `request.authorization["token"] == "a"`
    * `request.authorization.token == None`
    * (*parameters cannot overwrite pre-existing attributes of the `request.authorization` object*)
* `Authorization: Basic a` --> `request.authorization == None` (*Invalid base64 values with the Basic scheme will cause the entire `request.authorization` object to be `None`*)
* `Authorization: Basic AAAA` --> `request.authorization == 'Basic AAAAOg=='`
    * (*when the base64 is valid but does not have a colon in it [indicating the delimiter between username and password], this colon is somehow added to the end*)