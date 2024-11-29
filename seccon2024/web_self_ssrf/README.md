# self-ssrf&emsp;<sub><sup>Web, 193 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

The service implements the following endpoints:

- `GET /flag`: If the query parameter `flag` is equal to the flag, it responds with the flag.
- `GET /ssrf`: If the request's URL (as reported by express's `req.url`) is not an `http:` URL or is not on `localhost`, then it rejects the request.  Otherwise, it changes the URL's pathname to `/flag`, appends the `flag` query parameter with the flag, fetches the resulting URL, and returns the response.

Importantly, when fetching any endpoint, the service first checks if there is a `flag` query parameter present, and responds with a static page if it is not.

Based on how these endpoints work, we came up with two plans of attack for getting the flag:

1. Do it in the way the service seems to intend: use the `/ssrf` endpoint to get the server to request the `/flag` endpoint and reflect the flag back to us.  This is nontrivial because the request to `/ssrf` must include a `flag` parameter, so when one gets appended before the URL is forwarded, the result will be multiple `flag` parameters, which means that express will parse it as `flag` being an array and it will fail the strict equality check with the actual flag.
2. Convince the SSRF endpoint to fetch a URL that is not actually on `localhost`, likely by exploiting a URL parser differential between express's URL parser, the `URL` constructor, and the parser used internally by Bun in the `fetch()` function.

We spend a very long time on option 2, but ultimately weren't able to find a usable differential.

With only a couple of hours left, we changed strategies and opted for option 1, and focused in on how qs (used internally by express to parse the query parameters) does its parsing.  After reading through its parse function, we realized that, in an effort to properly parse objects, it [prioritizes `]=` over `=` when trying to decide where the separation between key and value is](https://github.com/ljharb/qs/blob/32e48a2f94f3a433dd69bf011356616c5e81f1a5/lib/parse.js#L100).  This is in contrast to the `URL` constructor, which doesn't understand the object notation at all and just looks for the first `=`.   Moreover, the `URL` constructor will normalize its output, meaning that a query parameter with multiple equals signs will get all subsequent equals signs percent-encoded.

This gives us an opportunity to craft a payload that express will parse as having a flag parameter the first time, which will then be modified by the `URL` parsing to no longer have a flag parameter (according to qs), which then gets the real flag appended to it.  The simplest solution to this is the following:

```
http://self-ssrf.seccon.games:3000/ssrf?flag[=]=
```

The first time this gets parsed, qs will parse it as

```
{
	flag: {
		"=": ""
	}
}
```

This is because it is prioritizing `]=` as the delimiter, so it treats the first `=` as part of the key.  When the `URL` constructor sees this URL, it will rewrite it as:

```
http://self-ssrf.seccon.games:3000/ssrf?flag[=]%3D
```

This is because it doesn't understand how the object notation works, so it just looks for the first `=` to end the key, and percent-encodes everything after that where needed to ensure that the value is properly understood by the backend.  Finally, the flag will be appended, and the final request will be for

```
http://self-ssrf.seccon.games:3000/ssrf?flag[=]%3D&flag=SECCON{...}
```

This time, qs will parse this as

```
{
	"flag[": "]=",
	"flag": "SECCON{...}"
}
```

So the server will return the flag to us.  A simple request to this URL in the browser gives us a response including the flag:

```
Congratz! The flag is 'SECCON{Which_whit3space_did_you_u5e?}'.
```
