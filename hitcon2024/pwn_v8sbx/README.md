# v8sbx
When I looked at it, the revenge challenge was already released, so there was probably a cheese solutions.
A quick diff revealed the following:
```bash
diff -qr v8sbx v8sbxrev
Files v8sbx/docker-compose.yml and v8sbxrev/docker-compose.yml differ
Files v8sbx/Dockerfile and v8sbxrev/Dockerfile differ
Only in v8sbxrev: flag
Only in v8sbxrev: readflag
Only in v8sbx/share: flag
```
A readflag binary was added. So I immediately assumed that you can just include the flag file in JavaScript.
The final payload was: `import("/home/ctf/flag")`
