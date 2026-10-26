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
  gateway, not a real provider key.
- Each `--llm-*` flag needs `--llm`. `--llm` does not work with `--no-connect`, because without a
  connection there are no tools to send. Both are usage errors (exit code 2).
- **Warning line:** before the first request, `scan` prints this line on stderr, also with `--json`:
  `mcpmoat scan: warning: --llm sends the name and description of every tool to the LLM provider
  <provider> at <host>. This data leaves your machine.`
- **What is sent:** one request for each tool of each server that `scan` inspected (status `ok`).
  The request holds the tool name (cut at 512 bytes) and the tool description (cut at 16 KiB, or
  less when the whole message would pass 24 KiB once it is JSON-escaped), with a flag that says
  that text was cut, and a fixed instruction text from mcpmoat. `--ignore` hides LLM findings from
  the report, but it does not stop a tool from being sent. To keep a server out of `--llm`, scan it
  with a separate config.
- **What mcpmoat never puts in a request:** your config files, env values, headers, args, URLs, the
  tool schemas and `pins.json`. The key goes only in the auth header of the provider.
- **The description goes as the server wrote it:** mcpmoat does not remove secret values from it.
  A server that got a token through its env or headers can put that token into a description, and
  `--llm` then sends it to the provider. Run `--llm` only if you accept that a tool description can
  leave your machine as the server wrote it.
- **No tool to send:** when no server was inspected, or the inspected servers list no tools,
  `scan` prints `mcpmoat scan: --llm had no tool to classify` on stderr. The exit code does not
  change.
- **Limits:** at most 500 tools in one scan and 4 requests at the same time. Each request has 30
  seconds. mcpmoat does not retry and does not follow redirects. The request and the response are
  each capped at 64 KiB. The cost of a scan grows with the number and the size of the tool
  descriptions. The LLM requests honour `HTTPS_PROXY` and `NO_PROXY`, like the connections to your
  servers, when the base URL is `https`. A base URL with `http` (a loopback host only) never uses a
  proxy.
- **Findings:** the model can answer only with a risk level and a category from a fixed list.
  mcpmoat shows no text from the model.
  - `MOAT-LLM-001`: the model rates the tool as risky. The severity is the risk level: `low`,
    `medium` or `high`, never `critical`. A risk level of `none` gives no finding.
  - `MOAT-LLM-002` (medium): the model refused, or its answer did not match the fixed format. A
    description written to confuse the model can cause this. Only an unusable model answer gives
    this finding. Any other error stops the LLM step (see **Exit codes** below).
  - When the model answers `none` or `low`, or the answer is unusable, for a tool whose name or
    description was cut, the tool gets one `MOAT-LLM-001` finding of severity `medium` with
    category `other`. An answer of `medium` or `high` keeps its severity and category. An unusable
    answer for a tool that was not cut still gives `MOAT-LLM-002`. The part after the cut was not
    rated and can hold the payload, and the risk text of the finding says so.

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
  hostile tool description can try to talk the model into a low rating. LLM findings only add to
  the rule findings. They never remove or change a rule finding, and they never change the pins.
- **What `--llm` does not check:** mcpmoat sends no input schema, so `--llm` does not rate text
  that is hidden in a parameter description of a schema.
- **Your API key and the servers:** mcpmoat does not pass the key to a server through the server
  environment or through a placeholder. `scan` and `pin` hide the variable from every placeholder. A
  `${MCPMOAT_LLM_API_KEY}` placeholder in a server config fails with an error. A placeholder with a
  default, such as `${MCPMOAT_LLM_API_KEY:-x}`, gets the default (see
  [Placeholders](stdio-servers.md#placeholders)). But a stdio server
  runs as your user and can read the environment of the mcpmoat process. Use a key made for this,
  with a low spend limit, for `--llm`.
- **Exit codes:** LLM findings count for `--fail-on` like any finding. A provider failure (a
  network, TLS or proxy error, a timeout, an HTTP error or a redirect, a response that is too
  large, or a response that is not a valid API answer) or more than 500 tools gives exit code 2.
  The report still prints, `complete` is `false` in JSON, and stderr says how many tools were not
  classified, for example
  `mcpmoat scan: the LLM provider failed (HTTP 401 (the API key was refused)); 12 tools were not classified`.
  An internal error of the LLM step also stops the step with exit code 2, and stderr then says
  `mcpmoat scan: the LLM step failed (internal error); 12 tools were not classified`. mcpmoat
  never prints the text of that error.
  A hostile server can cause this on purpose: it can list more than 500 tools, or write a
  description that makes the provider answer with an HTTP 4xx (a content filter or a context
  limit). The rule findings still print.
- **Ignore:** only `--ignore` works for `MOAT-LLM-001` and `MOAT-LLM-002`. `.mcpmoat-ignore`
  cannot ignore them, because the file can come from a cloned repository: `scan` keeps the finding
  and prints a warning (see [Ignore findings](ignore.md)). The ignored count on stderr
  includes the findings that `--ignore` drops.
- **OpenAI temperature:** the OpenAI request does not set a temperature, so models with a fixed
  temperature work.

## See also

- [The `--llm` classifier](ARCHITECTURE.md#the---llm-classifier)
- [Scan output](scan-output.md)
