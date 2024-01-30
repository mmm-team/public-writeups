# minioday&emsp;<sub><sup>Web, 290 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

> Old CVEs, try to pwn it for fun.

The service is a copy of minio version `2023-03-13T19-46-17Z`.  There are three CVEs that were fixed in the following version:

- CVE-2023-28432: Information disclosure (including secret keys and root passwords) in cluster deployments
- CVE-2023-28433: Arbitrary write on Windows due to a failure to filter `\` from paths
- CVE-2023-28434: Privlege escalation due to a faulty check in the `PostPolicyBucket` operation

Since the handout service is not running on Windows and is not a cluster deployment, we can rule out the first two CVEs.  The only prerequisite for the third is for the server to have browser console access enabled and for the attacker to have a credentials that are able to write to any bucket.  These are both true for the handout service (after extracting keys from the data directory in the handout), so we can use this vulnerability to attack the service.

There was surprisingly little documentation about CVE-2023-28434 (most of the resources we could find were about CVE-2023-28432 instead), so we set about rediscovering the vulnerability from the known conditions.  The `PostPolicyBucket` endpoint is used to allow an anonymous user to upload a file to a bucket, using a "policy" signed by a credentialed user that provides adequate authorization to do so.  Access to the bucket is checked via middleware that [checks if the bucket in question is a minio internal bucket](https://github.com/minio/minio/blob/440ad20c1d00eb4dddd0dfa9c2994b09079f5d97/cmd/generic-handlers.go#L400) and several other conditions are met, including that the request is not a browser request.  Knowing that the browser being enabled is a prerequisite for the vulnerability, we can assume that this is the check that does not behave properly.

[The browser check](https://github.com/minio/minio/blob/440ad20c1d00eb4dddd0dfa9c2994b09079f5d97/cmd/generic-handlers.go#L143) requires three conditions: browser access must be enabled; the `User-Agent` string must contain the string `Mozilla`; and the authentication type for the request must be anonymous.  The first two of these are easy, but the third is problematic because the `PostPolicyBucket` endpoint is only usable with a post policy signature, which is considered its own authentication type.

After poking at this for a while, we relized that [the check for this authentication type](https://github.com/minio/minio/blob/440ad20c1d00eb4dddd0dfa9c2994b09079f5d97/cmd/auth-handler.go#L76) could be defeated: it checks that the parsed mime type is exactly `multipart/form-data`, but it does not normalize this value first.  Therefore, we can use a mime type of `multipart/form-datA` to cause this condition to return false while still meeting [the condition for the endpoint](https://github.com/minio/minio/blob/440ad20c1d00eb4dddd0dfa9c2994b09079f5d97/cmd/api-router.go#L437) and allowing the request body to be parsed properly.

Therefore, we can use one of the minio client libraries to generate a post policy signature for any bucket, and then send that request with the headers `User-Agent: Mozilla` and `Content-Type: multipart/form-datA; ...` to successfully upload the file.  This is useful because minio stores its own internal account information in a bucket called `.minio.sys`, so we can upload a file to that bucket containing a custom access key to the path `.minio.sys/config/iam/service-accounts/<access-key-id>/identity.json/xl.meta` to get our own key on the server with no restrictions.

Once we have full permissions on the server, we can follow the attack path from [this repository that exploits CVE-2023-28432](https://github.com/AbelChe/evil_minio) by forcing the system to upgrade to a custom-built backdoored version of minio (made possible because `MINIO_UPDATE_MINISIGN_PUBKEY` was set to an empty string in the handout service).  The backdoor allows us to run arbitrary commands on the server, so we can simply `curl http://target-address/?alive=cat%20/flag` to get the flag.