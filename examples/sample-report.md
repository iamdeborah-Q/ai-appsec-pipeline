# Security Report

## Line 12 — true_positive
- Reason: The code uses pickle.dumps() to serialize data that is then passed as a URL parameter 'object'. This creates a deserialization vulnerability because an attacker can supply malicious pickled data via the URL parameter which will be unpickled elsewhere in the application, potentially leading to arbitrary code execution.
- Fix: Replace pickle with a safe serialization format like JSON. Use json.dumps() and json.loads() instead of pickle for serializing/deserializing data passed through URL parameters.

## Line 30 — true_positive ⚡ user-input on line
- Reason: Line 30 directly concatenates user-controlled input params['id'] from URL query string into SQL execute() without sanitization, enabling SQL injection
- Fix: Use parameterized query: cursor.execute('SELECT id, username, name, surname FROM users WHERE id=?', (params['id'],))

## Line 35 — true_positive ⚡ user-input on line
- Reason: Line 35 calls pickle.loads() directly on params["object"], which is user-controlled input from the URL query string (parsed on line 26). Pickle deserialization of untrusted data allows arbitrary code execution.
- Fix: Never use pickle to deserialize untrusted user input. Use safe serialization formats like JSON instead: json.loads(params["object"])

## Line 37 — true_positive ⚡ user-input on line
- Reason: The flagged line 37 directly passes attacker-controlled input params['path'] to urllib.request.urlopen() when the path contains '://'. This is a Server-Side Request Forgery (SSRF) vulnerability where an attacker can make the server send requests to arbitrary URLs.
- Fix: Validate and whitelist allowed URL schemes and domains. Use a URL parser to extract and validate components. Restrict to safe protocols (http/https only) and use an allowlist of permitted domains. Consider using a safe HTTP client library with SSRF protection.

## Line 39 — true_positive ⚡ user-input on line
- Reason: Line 39 directly concatenates attacker-controlled input params['domain'] into a shell command executed with shell=True, enabling command injection
- Fix: Use shell=False and pass command as a list: subprocess.run(['nslookup', params['domain']], shell=False, ...) or sanitize input to allow only valid domain characters

## Line 50 — true_positive ⚡ user-input on line
- Reason: Line 50 directly concatenates attacker-controlled input params['comment'] into a SQL query string without sanitization, creating a SQL injection vulnerability
- Fix: Use parameterized queries: cursor.execute('INSERT INTO comments VALUES(NULL, ?, ?)', (params['comment'], time.ctime()))

## Line 56 — true_positive ⚡ user-input on line
- Reason: Line 56 directly uses params["include"] in urllib.request.urlopen() without sanitization. The attacker-controlled input from the URL parameter flows directly into the dangerous urllib.request.urlopen() call, allowing SSRF attacks. Additionally, the result is then executed via exec() on line 57.
- Fix: Validate and whitelist the include parameter against allowed URLs/files. Do not allow user input to directly control urlopen(). Consider removing the remote URL feature entirely, or use a strict allowlist of permitted domains/schemes.

## Line 57 — true_positive
- Reason: Line 57 executes code from `program` variable which is populated on line 56 from `params["include"]` - either read from a file path or fetched via urlopen. This allows attacker-controlled input to reach exec() directly.
- Fix: Remove exec() functionality entirely or use a whitelist of allowed includes. Never execute untrusted code. Consider using template engines or safe include mechanisms instead.

## Line 67 — true_positive ⚡ user-input on line
- Reason: Line 67 directly concatenates user-controlled input params.get("password", "") into a SQL execute() call without sanitization. While username is sanitized with re.sub(r"[^\w]", "", ...), the password parameter is concatenated raw into the SQL query, allowing SQL injection.
- Fix: Use parameterized queries instead of string concatenation: cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (clean_username, password))
