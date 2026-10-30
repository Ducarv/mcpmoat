#!/usr/bin/env bash
# Builds mcpmoat and the fixture servers, and writes a private demo HOME.
# Usage: source docs/demo/setup.sh   (run it from the repo root; vhs does this)
# Works in bash on Linux and macOS.
# Switch the rug pull with: demo_flip
# Remove the demo folder and restore HOME, XDG_* and PATH with: demo_cleanup
# mcpmoat scan also reads project configs in the current folder (.mcp.json,
# .cursor/mcp.json, .claude/settings*.json); the repo root has none.
#
# The script is sourced, so it never uses set -e or exit: a failure must not
# close the caller's shell. Each step returns 1 instead.

write_config() { # $1 = rugpull args as a JSON array
  cat > "$DEMO_DIR/home/.claude.json" <<JSON
{"mcpServers":{
 "notes":{"command":"$DEMO_DIR/poisoned"},
 "math":{"command":"$DEMO_DIR/shadowing"},
 "mailer":{"command":"$DEMO_DIR/mailer"},
 "clock":{"command":"$DEMO_DIR/rugpull","args":$1}
}}
JSON
}

demo_flip() {
  if [ -z "${DEMO_DIR:-}" ]; then
    echo "demo_flip: no active demo; source docs/demo/setup.sh first" >&2
    return 1
  fi
  write_config '["-variant","injected"]'
}

demo_cleanup() {
  # Remove only a direct child "mcpmoat-demo.*" of the cache folder.
  local name="${DEMO_DIR#"${DEMO_CACHE:-}"/}"
  if [ -z "${DEMO_CACHE:-}" ] || [ -z "${DEMO_DIR:-}" ] || [ "$name" = "$DEMO_DIR" ] ||
    [[ "$name" != mcpmoat-demo.?* || "$name" == */* ]]; then
    echo "demo_cleanup: refusing to remove '${DEMO_DIR:-}'" >&2
    return 1
  fi
  rm -rf -- "$DEMO_DIR"
  export HOME="$DEMO_OLD_HOME" PATH="$DEMO_OLD_PATH"
  if [ -n "${DEMO_OLD_XDG_CONFIG_HOME+x}" ]; then
    export XDG_CONFIG_HOME="$DEMO_OLD_XDG_CONFIG_HOME"
  else
    unset XDG_CONFIG_HOME
  fi
  if [ -n "${DEMO_OLD_XDG_CACHE_HOME+x}" ]; then
    export XDG_CACHE_HOME="$DEMO_OLD_XDG_CACHE_HOME"
  else
    unset XDG_CACHE_HOME
  fi
  unset DEMO_DIR DEMO_CACHE DEMO_OLD_HOME DEMO_OLD_PATH \
    DEMO_OLD_XDG_CONFIG_HOME DEMO_OLD_XDG_CACHE_HOME
}

_demo_setup() {
  if [ -n "${DEMO_DIR:-}" ]; then
    echo "setup.sh: a demo is already active in '$DEMO_DIR'; run demo_cleanup first" >&2
    return 1
  fi

  # mcpmoat refuses a run folder below a folder that other users can write to,
  # such as /tmp, so the demo folder goes below the private user cache.
  # Compute it before HOME changes.
  DEMO_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
  # The XDG spec says to ignore a relative path.
  case $DEMO_CACHE in /*) ;; *) DEMO_CACHE=$HOME/.cache ;; esac
  # The folder name goes into a JSON here-doc and into PATH: refuse quotes,
  # backslashes, ':' and other special characters.
  case $DEMO_CACHE in
    *[!A-Za-z0-9/._\ -]*)
      echo "setup.sh: unsupported characters in '$DEMO_CACHE'; set XDG_CACHE_HOME to a plain path" >&2
      unset DEMO_CACHE
      return 1
      ;;
  esac
  if [ ! -d "$DEMO_CACHE" ]; then
    (umask 077 && mkdir -p "$DEMO_CACHE") || { unset DEMO_CACHE; return 1; }
  fi
  if [ -n "$(find -H "$DEMO_CACHE" -maxdepth 0 \( -perm -020 -o -perm -002 \))" ]; then
    echo "setup.sh: group or others can write to '$DEMO_CACHE'; run: chmod go-w '$DEMO_CACHE'" >&2
    unset DEMO_CACHE
    return 1
  fi

  DEMO_DIR="$(mktemp -d "$DEMO_CACHE/mcpmoat-demo.XXXXXX")" || {
    unset DEMO_DIR DEMO_CACHE
    return 1
  }

  # Only mcpmoat goes on PATH. The config names the fixtures by absolute path.
  # -m 700 on home: with umask 002 a plain mkdir makes HOME group-writable,
  # and the run folder check would refuse it.
  local s ok=1
  mkdir "$DEMO_DIR/bin" && mkdir -m 700 "$DEMO_DIR/home" &&
    go build -o "$DEMO_DIR/bin/mcpmoat" ./cmd/mcpmoat || ok=
  for s in poisoned shadowing mailer rugpull; do
    [ -n "$ok" ] || break
    go build -o "$DEMO_DIR/$s" "./testdata/servers/$s" || ok=
  done
  [ -z "$ok" ] || write_config '[]' || ok=
  if [ -z "$ok" ]; then
    echo "setup.sh: build failed; removed '$DEMO_DIR'" >&2
    rm -rf -- "$DEMO_DIR"
    unset DEMO_DIR DEMO_CACHE
    return 1
  fi

  # Save the caller's values; demo_cleanup restores them. An unset XDG
  # variable stays unset in the saved copy, and demo_cleanup unsets it again.
  unset DEMO_OLD_XDG_CONFIG_HOME DEMO_OLD_XDG_CACHE_HOME
  DEMO_OLD_HOME="$HOME"
  DEMO_OLD_PATH="$PATH"
  [ -z "${XDG_CONFIG_HOME+x}" ] || DEMO_OLD_XDG_CONFIG_HOME="$XDG_CONFIG_HOME"
  [ -z "${XDG_CACHE_HOME+x}" ] || DEMO_OLD_XDG_CACHE_HOME="$XDG_CACHE_HOME"

  export HOME="$DEMO_DIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_CACHE_HOME="$HOME/.cache"
  export PATH="$DEMO_DIR/bin:$PATH"
}

if _demo_setup; then
  unset -f _demo_setup
  echo "mcpmoat demo ready"
else
  unset -f _demo_setup
  return 1
fi
