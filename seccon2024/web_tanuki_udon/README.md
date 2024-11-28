## tanuki udon - @disna

* web
* 41 solves
* 149 points

> Inspired by [Udon (TSG CTF 2021)](https://github.com/tsg-ut/tsgctf2021/tree/main/web/udon)
>
> Challenge: http://tanuki-udon.seccon.games:3000
>
> Admin bot: http://tanuki-udon.seccon.games:1337
>
> [Tanuki_Udon.tar.gz](tanuki_udon.tar.gz) c176e73baabeac73110e9edef582624e773713e9
>
> author: Satoooon

(Forewarning: the file we downloaded does not have the same checksum as what is written in the challenge description)

`Tanuki Udon` is a simple note app, where the goal is to steal a note containing the flag that an admin bot creates. At a glance we see that these notes are reflected raw to the user, bar a `markdown(content)` pass, and so offers an inviting XSS sink:

```ejs
    <section>
      <%- note.content %>
    </section>
```
_note.ejs_

```js
app.get('/note/:noteId', (req, res) => {
  const { noteId } = req.params;
  const note = db.getNote(noteId);
  if (!note) return res.status(400).send('Note not found');
  res.render('note', { note });
});

app.post('/note', (req, res) => {
  const { title, content } = req.body;
  req.user.addNote(db.createNote({ title, content: markdown(content) }));
  res.redirect('/');
});
```
_index.js_

```js
const escapeHtml = (content) => {
  return content
    .replaceAll('&', '&amp;')
    .replaceAll(`"`, '&quot;')
    .replaceAll(`'`, '&#39;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

const markdown = (content) => {
  const escaped = escapeHtml(content);
  return escaped
    .replace(/!\[([^"]*?)\]\(([^"]*?)\)/g, `<img alt="$1" src="$2"></img>`)
    .replace(/\[(.*?)\]\(([^"]*?)\)/g, `<a href="$2">$1</a>`)
    .replace(/\*\*(.*?)\*\*/g, `<strong>$1</strong>`)
    .replace(/  $/mg, `<br>`);
}
```
_markdown.js_

Quotes in user input are sanitized to prevent context escape (e.g., escape `src` attribute value context to define a new attribute), but this is bypasseable by nesting markdown elements within each other; `![[AAA](BBB)](CCC)` transforms into `<img alt="`<span style="opacity:0.2;">`<a href=`</span>`"CCC">`<span style="opacity:0.2;">`AAA" src="BBB"></img></a>`</span>, where `CCC` is parsed as an attribute name, and which we fully control.

A common XSS trick is to set both `src=x` and `onload="<javascript payload>"`, but we do not get quotes, and we cannot use closing round brackets i.e., `)` because it messes with `.replace`. So, we make sure our `onerror` payload does not contain spaces, and we use [tagged template literals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#tagged_templates) to call functions instead:

```python
base64_payload = base64.b64encode(script.encode()).decode()
payload = f"![![AAA](BBB)](src=x onerror=a=atob`{base64_payload}`;eval.call`a${{a}}`//)"
```

Then with unrestricted XSS on the challenge domain, it's just a matter of grabbing the list of notes from `/`, navigating to admin's flag note, and exfiltrating it to ourselves. [Solve script](script.py) here.

`SECCON{Firefox Link = Kitsune Udon <-> Chrome Speculation-Rules = Tanuki Udon}`

(fwiw, this is an unintended solution as the challenge had a lot more bells and whistles to it than just the parts shown here, but flag is flag :P)