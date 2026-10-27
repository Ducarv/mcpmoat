# Optional LLM classification (sends data off your machine)

**Warning: `scan --llm` sends the name and description of every inspected tool to an LLM provider.
This data leaves your machine.** The option is off by default. Without `--llm`, mcpmoat reads no
API key and sends nothing to an LLM provider.

```sh
mcpmoat scan --llm                                                # Anthropic API, default model
mcpmoat scan --llm --llm-provider openai --llm-model <model>      # OpenAI API
mcpmoat scan --llm --llm-provider openai --llm-model <model> \
  --llm-base-url http://127.0.0.1:8080/v1                         # a local OpenAI-compatible server
```

- **API key:** mcpmoat reads it only from the `MCPMOAT_LLM_API_KEY` environment variable. There is no
  flag for it, because command-line arguments show in `ps` and in your shell history. With `--llm`
  and no key, `scan` exits with code 2 and names the variable. A local server needs a key too: use
  any value that it accepts (see `--llm-base-url` below).
- **`--llm-provider anthropic|openai`:** the API. The default is `anthropic`. `openai` also works
  with a server that speaks the OpenAI Chat Completions API.
- **`--llm-model <name>`:** the model. It is required for `openai`. `mcpmoat scan -h` shows the
  default model for `anthropic`.
- **`--llm-base-url <url>`:** the base URL of the API. The default is the public API of the
  provider. It must use `https`, or `http` only for a loopback host such as `127.0.0.1` or
  `localhost`. With `http`, every address that the host name resolves to must be a loopback
  address. Otherwise `scan` refuses the URL and sends no request. A user name, a password, a query
  or a fragment in the URL is refused. With an `http` base URL, any process on this machine that
  listens on that port gets the key in clear text. So use a key made for that local server or
  gateway, not a real provider key. The error text of a wrong argument hides the value of
  `--llm-base-url` and the user info of any URL, with some limits (see
  [What mcpmoat does not do](limits.md)).
- Each `--llm-*` flag needs `--llm`. `--llm` does not work with `--no-connect`, because without a
  connection there are no tools to send. Both are usage errors (exit code 2).
- **Warning line:** before the first request, `scan` prints this line on stderr, also with `--json`:
  `mcpmoat scan: warning: --llm sends the name and description of every tool to the LLM provider
  <provider> at <host>. This data leaves your machine.`
- **What is sent:** one request for each tool of each server that `scan` inspected (status `ok`).
  The request holds the tool name (cut at 512 bytes) and the tool description (cut at 16 KiB, or
  less when the whole message would pass 24 KiB once it is JSON-escaped), with a flag that says
  that text was cut, and a fixed instruction text from mcpmoat. Before the first request, `scan`
  prints the number of tools and the size of their text on stderr, also with `--json`:
  `mcpmoat scan: sending 42 tools (about 37 KiB of text) to the LLM provider`. The line holds
  numbers only. The size counts the names and descriptions after the cut, so it is approximate.
  With no tool to send, this line does not show. `--ignore` hides LLM findings from
  the report, but it does not stop a tool from being sent. To keep a server out of `--llm`, scan it
  with a separate config.
- **What mcpmoat never puts in a request:** your config files, env values, headers, args, URLs, the
  tool schemas and `pins.json`. The key goes only in the auth header of the provider.
- **Credentials are removed from the tool text:** a server that got a token through its env,
  headers or args can put that token into a tool name or description. So before the cut, mcpmoat
  replaces each configured value of the server that looks like a credential with `********` in
  the name and the description of the tools of that server. A configured value is a credential
  in these cases:
  - An env value, when the key looks secret (`API_KEY`, `GITHUB_TOKEN`), or when the value looks
    like a token or holds a credential. So `DATABASE_URL=postgres://app:pw@db/prod` counts, but
    `NODE_ENV=production` does not. The credential pieces inside an env value, an expanded value
    or a header value count too, by the same rules as the args below. So the password of
    `postgres://app:pw@db/prod` is removed when a server echoes it alone (when it has 8 bytes or
    more).
  - A header value, when the header name looks secret (`Authorization`, `Proxy-Authorization`,
    `Cookie`, `X-Api-Key`, or any name with a word such as `key` or `session`), when the value is
    an auth scheme and a credential (`Bearer <token>`, `Basic <base64>`, `Token <token>`), or when
    the value looks like a token. Then all the parts of that header count: the whole value, the
    credential after the scheme, and the base64 text and the password of a `Basic` value. A
    `Cookie` or `Cookie2` header always counts: the whole value, and each `name=value` pair and
    each value in it, so a server that echoes one cookie value alone is found. Every pair counts,
    also a plain one such as `theme=dark`, so the check fails closed. A `Set-Cookie` header always
    counts too, but only its first pair is a cookie. The attributes after it (`Path=/`,
    `Domain=example.com`, `Expires=...`) are not pairs, so they do not count alone.
    `Content-Type: application/json` and a plain `User-Agent` do not count.
  - In the URL: the whole user info and the password, always. A query or path part, or the value
    inside a `key=value` path segment or a matrix parameter (`;token=x`), only when its key looks
    secret (`?api_key=x`) or it looks like a token. So `?workspace=engineering` does not count.
  - The value of an expanded placeholder, when the variable name looks secret or the value looks
    like a token or holds a credential.
  - For a stdio server, the parts of the command and the args (after the expansion) that look like
    a credential: the value of a secret-like flag or key (`--api-key V`, `--token=V`,
    `GITHUB_TOKEN=V`, `"token":"V"`, libpq `password=V`), the password of a user flag
    (`-u admin:pw`), the value after a secret-like header name in `-H` (`Authorization: Bearer
    tok`), the credential after an auth scheme, the user info and the secret parts of a URL, and
    each piece that looks like a token, such as `-p<token>` or `<token>=1`. The plain words of a
    DSN (`host=localhost dbname=production user=postgres`), a path segment `My Documents`,
    package names and other plain args do not count.
  - The password of a DSN with no scheme: in `app:pw@db:5432/prod` and `app:pw@tcp(db:3306)/prod`
    it is the text between the first `:` and the last `@`. It counts alone, in the args and inside
    an env value, an expanded value or a header value. The password of the Oracle form
    `scott/pw@orcl`, and of a positional `admin:pw`, counts only when the whole value counts:
    after a secret-like flag (`--password scott/pw@orcl`) or when the value looks like a token.
    `git@github.com:org/repo` and `user@example.com` hold no password.

  A word looks like a token when it starts with a known token prefix (`ghp_`, `sk-`), is a UUID,
  has 20 bytes or more with letters and digits, or has 32 bytes or more. A value of one server is
  removed only from the tools of that server. For a
  value that is not valid UTF-8 (it can come from your environment), mcpmoat also removes the form
  that the server sends in JSON, with one U+FFFD for each invalid byte. When a `********` starts in
  the part of the name or the description that mcpmoat can send (the first 512 bytes of the name
  or the first 16 KiB of the description, plus one byte), the user message also has
  `"redacted": true`, also when a cut then removes the `********`. A value after that part is never
  sent, so it does not set the flag. The fixed instruction text tells the model that `********` is
  removed text and not an instruction. The limits:
  - **Trade-off:** a plain config value that a server echoes reaches the provider. For example,
    the env value `production` of `NODE_ENV`, or a password under a key that does not look secret
    (such as `DB_SETTING`) when the password does not look like a token. Earlier versions removed
    every configured value of 8 bytes or more. Now mcpmoat removes only credentials, so a plain
    word of your config no longer hides a part of a benign description from the model. The local
    report still masks every configured value (see [Scan output](scan-output.md)).
  - A value shorter than 8 bytes is not removed, because it would also hide ordinary words such as
    `true` or `json`.
  - An encoded form of a value is not removed, for example the value in base64, URL-encoded, or
    split with spaces. A value that holds a backslash sequence (the `\t` and `\n` of the Windows
    path `C:\tools\new_dir`) is not found when the server sends a real tab and newline there, and
    the JSON of the request then shows the same escapes.
  - The check fails closed: mcpmoat also removes some text that is not secret. A word of 32 bytes
    or more counts as a token, also a readable path segment (such as a segment of the macOS
    `$TMPDIR`), and so does a nix hash or a UUID. A header value that starts with an auth scheme
    word counts as a credential, also when it is not one (`Token count`). When such text is in a
    tool description, the model sees `********` in its place, and the message has
    `"redacted": true`.
  - The decoded text `name:password` of a `Basic` header value is not removed as a whole. Only the
    password in it is removed (when it has 8 bytes or more), so the model sees the name.
  - Some secrets in args are not found, so they are not removed: a value after a flag whose name
    does not look secret (`--db mypassword`), a plain positional value (`hunter2`), a short path
    segment, or a value glued to a short flag when the whole arg does not look like a token
    (`-phunter2`, `-pghp_abc123`).
  - A secret that starts or ends with `*`, or that holds a whole `********`, can show again across
    a `********`. For example, the secret `abcdefg*` shows when the text has `abcdefg` just before
    another secret.
  - A server can write `********` in its text itself, so the marker does not prove that mcpmoat
    removed a secret.
- **No tool to send:** when no server was inspected, or the inspected servers list no tools,
  `scan` prints `mcpmoat scan: --llm had no tool to classify` on stderr. The exit code does not
  change.
- **Limits:** at most 500 tools in one scan and 4 requests at the same time. Each request has 30
  seconds, also each retry. mcpmoat does not follow redirects. The request and the response are
  each capped at 64 KiB. The whole LLM step has 10 minutes (see **Time limit** below). The cost of
  a scan grows with the number and the size of the tool descriptions. There is no cap on the total
  size of a scan, but the caps above bound it: at most 3 requests for each tool (see **Retries**
  below), so at most 1500 requests in one scan, each with at most 24 KiB of tool text. The LLM
  requests honour `HTTPS_PROXY` and `NO_PROXY`, like the connections to your servers, when the
  base URL is `https`. A base URL with `http` (a loopback host only) never uses a proxy.
- **Retries:** when the provider answers HTTP 429, 502, 503, 504 or 529 (busy or overloaded),
  mcpmoat sends the same request again. Each tool gets at most 3 tries in total: the first request
  and 2 retries. Before a retry, mcpmoat waits about 1 second, then about 2 seconds, with jitter: a
  random part makes each wait 0.5 to 1.5 times that value. When the answer has a `Retry-After`
  header (a number of seconds or an HTTP date), mcpmoat waits that time instead. A `Retry-After` of
  up to 30 seconds is honoured; a longer one means no retry. A `Retry-After` that is longer than
  the time left in the 10 minutes of the step also means no retry: mcpmoat does not wait, and the
  tool fails at once with the error of the provider. The scan then ends with exit code 2, and the
  stderr line shows the status of the provider (see **Exit codes** below). A value that is not valid, or a date in
  the past, gives the normal wait. mcpmoat never reads the body of an HTTP error. These cases get no
  retry: any other HTTP error (also 400, 413, 422, 401, 403, 404 and 500), a redirect, a request
  that used up its 30 seconds, and any other network error. When the last try fails, it is a
  provider failure (see **Exit codes** below).
- **Time limit:** the whole LLM step stops after 10 minutes. No flag changes this limit. The tools
  that got an answer keep their findings. The other tools are not classified, and `scan` exits
  with code 2 (see **Exit codes** below).
- **Output cap:** an Anthropic request caps the model answer at 200 tokens. An OpenAI request to
  the default base URL sets `max_completion_tokens` to 2048. The reason: a reasoning model bills
  hidden reasoning tokens, and the 64 KiB response cap does not limit them. A request to any other
  base URL (an OpenAI-compatible server) sets no output cap, because many of these servers know
  only `max_tokens` and refuse `max_completion_tokens`. An answer that the cap cuts is an unusable
  answer: a `MOAT-LLM-002` finding, not exit code 2. So mcpmoat does not cap the cost of hidden
  reasoning tokens for a base URL that is not the default. To cap that cost, set a spend limit in
  the account of the provider.
- **How the 500 tools are shared:** the servers share the cap fairly. A server with fewer tools
  than an equal part keeps all its tools, and the part that it does not use goes to the larger
  servers. When the parts cannot be equal, the servers that come first in the scan get one tool
  more. For example, three servers with 3, 1000 and 1000 tools send 3, 249 and 248 tools. Each
  server sends its first tools, in the order that it lists them. So one server with many tools
  cannot leave the other servers without a rating.
- **Findings:** the model can answer only with a risk level and a category from a fixed list.
  mcpmoat shows no text from the model.
  - `MOAT-LLM-001`: the model rates the tool as risky. The severity is the risk level: `low`,
    `medium` or `high`, never `critical`. A risk level of `none` gives no finding.
  - `MOAT-LLM-002` (medium): the model refused, or its answer did not match the fixed format. A
    description written to confuse the model can cause this. It also reports a tool that the
    provider refused with HTTP 400, 413 or 422, for example because of a safety filter or a size
    limit. That tool was not classified, and its risk text is `The LLM provider refused this tool
    description (HTTP 4xx), so the tool was not classified. A safety filter or a size limit of the
    provider can cause this.` The other requests go on. Only an unusable model answer and these
    three codes give this finding. Any other error stops the LLM step (see **Exit codes** below).
  - When the model answers `none` or `low`, or the answer is unusable, or the provider refused the
    tool, for a tool whose name or description was cut, the tool gets one `MOAT-LLM-001` finding of
    severity `medium` with category `other`. An answer of `medium` or `high` keeps its severity and
    category. An unusable answer or a refusal for a tool that was not cut still gives
    `MOAT-LLM-002`. The part after the cut was not rated and can hold the payload, and the risk
    text of the finding says so.
  - The same floor applies to a tool from whose name or description mcpmoat removed a credential
    (see **Credentials are removed from the tool text** above), that is, when the message
    has `"redacted": true`. When the model answers `none` or `low`, or the answer is unusable, or
    the provider refused the tool, the tool gets one `MOAT-LLM-001` finding of severity `medium`
    with category `other`. An answer of `medium` or `high` keeps its severity and category. The
    risk text is `A value from your config, such as an env or header value, was removed from the
    tool text before it was sent to the model. The removed text was not rated and can hold hidden
    instructions for the AI agent.` The reason: a hostile config can choose which text mcpmoat
    removes, so a part of a malicious description may never reach the model. For example, a config
    can put an injection phrase in an env value under a secret-like key: mcpmoat removes the
    phrase, and the floor still gives the tool a `medium` finding. A phrase under a key that does
    not look secret is not removed, so the model reads it. When the text was also cut, the finding
    has the text of the cut. Text that mcpmoat removes but that is not secret (see the fail-closed
    limit above) gives the same floor. Read the description to check such a finding. It is
    `medium`, so it does not change the exit code under the default `--fail-on high`, but
    `--fail-on medium` gives exit 1. What you see: a tool whose description echoes a credential
    from your config gets a `medium` finding. That is also a sign that the server echoes a secret.
    The floor does not make the rating complete. The rule engine still reads the full text, and a
    `medium` finding is below the default `--fail-on high`.

  An LLM finding is marked `[LLM]` and has a `Source` line. In JSON its `source` is `llm`, and
  `related` holds the category. A short sample:

  ```text
  HIGH (1)
    MOAT-LLM-001  Language model rates this tool as risky [LLM]
      Server: files (cursor, global)
      Source: LLM classification (advisory)
      Tool: read_file (credential-access)
      Risk: An LLM classifier rated this tool description as likely to make the AI agent read ...
      Fix: Read the full tool description and check it by hand. ...
  ```

- **Advisory only:** a model can be wrong. No LLM finding does not mean that a tool is safe. A
  hostile tool description can try to talk the model into a low rating. It can also make the
  provider refuse it (HTTP 400, 413 or 422) or make the model answer unusable. The tool then gets
  a `medium` finding at most (`MOAT-LLM-002`, or the `MOAT-LLM-001` floor of a cut or redacted tool), below
  the default `--fail-on high`. So a hostile server can keep its LLM rating from reaching `high`.
  The rule findings still apply, and the LLM row still shows. LLM findings only add to the rule
  findings. They never remove or change a rule finding, and they never change the pins.
- **What `--llm` does not check:** mcpmoat sends no input schema, so `--llm` does not rate text
  that is hidden in a parameter description of a schema.
- **Your API key and the servers:** mcpmoat does not pass the key to a server through the server
  environment or through a placeholder. `scan` and `pin` hide the variable from every placeholder. A
  `${MCPMOAT_LLM_API_KEY}` placeholder in a server config fails with an error. A placeholder with a
  default, such as `${MCPMOAT_LLM_API_KEY:-x}`, gets the default (see
  [Placeholders](stdio-servers.md#placeholders)). But a stdio server
  runs as your user and can read the environment of the mcpmoat process. Use a key made for this,
  with a low spend limit, for `--llm`.
- **Exit codes:** LLM findings count for `--fail-on` like any finding. A tool that the provider
  refused (HTTP 400, 413 or 422) is a finding, not an error: it alone does not give exit code 2,
  and `complete` can stay `true`. These cases give exit code 2:
  - A provider failure: a network, TLS or proxy error, a timeout, any other HTTP error (also 401,
    403 and 404) or a redirect, a response that is too large, or a response that is not a valid
    API answer. For HTTP 429, 502, 503, 504 and 529, this is the failure of the last try (see
    **Retries** above). The first failure stops the step. stderr says how many tools were not
    classified, for example
    `mcpmoat scan: the LLM provider failed (HTTP 401 (the API key was refused)); 12 tools were not classified`.
  - The time limit of the step (10 minutes). The running requests stop, and stderr says
    `mcpmoat scan: the LLM step stopped after 10 minutes; 12 tools were not classified`. When a
    provider failure came first, stderr shows that failure instead. A provider failure that came
    at almost the same time as the limit can show as the time limit. A signal (Ctrl-C) is not this
    case: it prints no report (see [Exit codes](exit-codes.md)).
  - The provider refused every tool that it answered: at least one tool got HTTP 400, 413 or 422,
    and no tool got a 2xx answer (a verdict, or a model answer that cannot be used). A wrong model
    name or API shape can cause this, so mcpmoat fails closed. No tool gets an LLM finding then,
    and stderr says, with the code of the first refused tool in the scan order,
    `mcpmoat scan: the LLM provider failed (HTTP 400, the provider refused every tool); 12 tools were not classified`.
  - An internal error of the LLM step. stderr then says
    `mcpmoat scan: the LLM step failed (internal error); 12 tools were not classified`. mcpmoat
    never prints the text of that error.
  - Tools over the share of their server of the 500-tool cap. They are not sent, and stderr says
    `mcpmoat scan: --llm classifies at most 500 tools in one scan; 12 tools were not classified`,
    with the total for all the servers.

  In each case the report still prints, and `complete` is `false` in JSON. A hostile server can
  still cause exit code 2 on purpose: it can list more tools than its share. When its tools are
  the only tools in the step, it can also write descriptions that the provider refuses. The rule
  findings still print.
- **Ignore:** only `--ignore` works for `MOAT-LLM-001` and `MOAT-LLM-002`. `.mcpmoat-ignore`
  cannot ignore them, because the file can come from a cloned repository: `scan` keeps the finding
  and prints a warning (see [Ignore findings](ignore.md)). The ignored count on stderr
  includes the findings that `--ignore` drops.
- **OpenAI temperature:** the OpenAI request does not set a temperature, so models with a fixed
  temperature work.

## See also

- [The `--llm` classifier](ARCHITECTURE.md#the---llm-classifier)
- [Scan output](scan-output.md)
