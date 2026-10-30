# shellcheck shell=bash
# Builds mcpmoat and the fixture servers, and writes a private demo HOME.
# Usage: source docs/demo/setup.sh   (from the repo root). See docs/demo/README.md.
#
# The file is sourced, so it never uses set -e: a failure must not close the
# caller's shell. Each step returns 1 instead.

# Refuse to run as a script: the demo must change the caller's shell.
# zsh accepts a top-level return in a script, so it needs ZSH_EVAL_CONTEXT.
if [ -n "${ZSH_VERSION:-}" ]; then
  case $ZSH_EVAL_CONTEXT in *:file*) ;; *) false ;; esac
else
  (return 0 2>/dev/null)
fi || {
  echo "setup.sh: source this file, do not run it" >&2
  exit 1
}

if [ -n "${MCPMOAT_DEMO_DIR:-}" ]; then
  echo "setup.sh: a demo is already active in '$MCPMOAT_DEMO_DIR'; run demo_cleanup first" >&2
  return 1
fi

_demo_write_config() { # $1 = rugpull args as a JSON array
  cat >"$MCPMOAT_DEMO_DIR/home/.claude.json" <<JSON
{"mcpServers":{
 "notes":{"command":"$MCPMOAT_DEMO_DIR/poisoned"},
 "math":{"command":"$MCPMOAT_DEMO_DIR/shadowing"},
 "mailer":{"command":"$MCPMOAT_DEMO_DIR/mailer"},
 "clock":{"command":"$MCPMOAT_DEMO_DIR/rugpull","args":$1}
}}
JSON
}

# Removes the demo folder (if any), restores the saved variables and forgets
# the demo. Each variable comes back only if setup.sh saved it.
_demo_reset() {
  [ -z "${MCPMOAT_DEMO_DIR:-}" ] || rm -rf -- "$MCPMOAT_DEMO_DIR"
  [ -z "${MCPMOAT_DEMO_OLD_PATH+x}" ] || export PATH="$MCPMOAT_DEMO_OLD_PATH"
  # The XDG values are saved in the same step as HOME. An unset saved copy
  # means the variable was unset.
  if [ -n "${MCPMOAT_DEMO_OLD_HOME+x}" ]; then
    export HOME="$MCPMOAT_DEMO_OLD_HOME"
    if [ -n "${MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME+x}" ]; then
      export XDG_CONFIG_HOME="$MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME"
    else
      unset XDG_CONFIG_HOME
    fi
    if [ -n "${MCPMOAT_DEMO_OLD_XDG_CACHE_HOME+x}" ]; then
      export XDG_CACHE_HOME="$MCPMOAT_DEMO_OLD_XDG_CACHE_HOME"
    else
      unset XDG_CACHE_HOME
    fi
  fi
  unset MCPMOAT_DEMO_DIR MCPMOAT_DEMO_CACHE MCPMOAT_DEMO_OLD_HOME \
    MCPMOAT_DEMO_OLD_PATH MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME \
    MCPMOAT_DEMO_OLD_XDG_CACHE_HOME
}

demo_flip() {
  if [ -z "${MCPMOAT_DEMO_DIR:-}" ]; then
    echo "demo_flip: no active demo; source docs/demo/setup.sh first" >&2
    return 1
  fi
  _demo_write_config '["-variant","injected"]'
}

demo_cleanup() {
  # Remove only a direct child "mcpmoat-demo.*" of the cache folder.
  local dir="${MCPMOAT_DEMO_DIR:-}" cache="${MCPMOAT_DEMO_CACHE:-}" name safe=
  name="${dir#"$cache"/}"
  case $name in
    "$dir" | */*) ;; # not below the cache folder, or not a direct child
    mcpmoat-demo.?*) [ -z "$cache" ] || safe=1 ;;
  esac
  if [ -z "$safe" ]; then
    echo "demo_cleanup: refusing to remove '$dir'" >&2
    return 1
  fi
  _demo_reset
  unset -f _demo_write_config _demo_reset demo_flip demo_cleanup
}

_demo_setup() {
  # C locale: in bash 3.2 the A-Za-z range below also matches letters like é.
  local LC_ALL=C s
  # zsh puts the caller's INT trap back when this function returns.
  [ -z "${ZSH_VERSION:-}" ] || setopt local_options local_traps
  # Ctrl-C: remove the half-built demo. bash 3.2 and zsh drop the 1 of this
  # return, so the caller checks MCPMOAT_DEMO_DIR, which _demo_reset unsets.
  trap '_demo_reset; return 1' INT

  # Save the caller's values before the demo folder exists.
  MCPMOAT_DEMO_OLD_HOME="$HOME"
  MCPMOAT_DEMO_OLD_PATH="$PATH"
  unset MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME MCPMOAT_DEMO_OLD_XDG_CACHE_HOME
  [ -z "${XDG_CONFIG_HOME+x}" ] || MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME="$XDG_CONFIG_HOME"
  [ -z "${XDG_CACHE_HOME+x}" ] || MCPMOAT_DEMO_OLD_XDG_CACHE_HOME="$XDG_CACHE_HOME"

  # mcpmoat refuses a run folder below a folder that other users can write to,
  # such as /tmp, so the demo folder goes below the private user cache.
  MCPMOAT_DEMO_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
  # The XDG spec says to ignore a relative path.
  case $MCPMOAT_DEMO_CACHE in /*) ;; *) MCPMOAT_DEMO_CACHE=$HOME/.cache ;; esac
  # The folder name goes into a JSON here-doc and into PATH: refuse quotes,
  # backslashes, ':' and other special characters.
  case $MCPMOAT_DEMO_CACHE in
    *[!A-Za-z0-9/._\ -]*)
      echo "setup.sh: unsupported characters in '$MCPMOAT_DEMO_CACHE'; set XDG_CACHE_HOME to a plain path" >&2
      return 1
      ;;
  esac
  if [ ! -d "$MCPMOAT_DEMO_CACHE" ]; then
    (umask 077 && mkdir -p "$MCPMOAT_DEMO_CACHE") || return 1
  fi
  if [ -n "$(find -H "$MCPMOAT_DEMO_CACHE" -maxdepth 0 \( -perm -020 -o -perm -002 \))" ]; then
    echo "setup.sh: group or others can write to '$MCPMOAT_DEMO_CACHE'; run: chmod go-w '$MCPMOAT_DEMO_CACHE'" >&2
    return 1
  fi

  MCPMOAT_DEMO_DIR="$(mktemp -d "$MCPMOAT_DEMO_CACHE/mcpmoat-demo.XXXXXX")" || return 1

  # Only mcpmoat goes on PATH. The config names the fixtures by absolute path.
  # -m 700 on home: with umask 002 a plain mkdir makes HOME group-writable,
  # and the run folder check would refuse it.
  mkdir "$MCPMOAT_DEMO_DIR/bin" || return 1
  mkdir -m 700 "$MCPMOAT_DEMO_DIR/home" || return 1
  go build -o "$MCPMOAT_DEMO_DIR/bin/mcpmoat" ./cmd/mcpmoat || return 1
  for s in poisoned shadowing mailer rugpull; do
    go build -o "$MCPMOAT_DEMO_DIR/$s" "./testdata/servers/$s" || return 1
  done
  _demo_write_config '[]' || return 1
  # A Ctrl-C in a nested call can return here with status 0.
  [ -n "${MCPMOAT_DEMO_DIR:-}" ] || return 1

  export HOME="$MCPMOAT_DEMO_DIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_CACHE_HOME="$HOME/.cache"
  export PATH="$MCPMOAT_DEMO_DIR/bin:$PATH"
}

# zsh cannot list traps in $(...); local_traps restores its trap instead.
[ -n "${ZSH_VERSION:-}" ] || _demo_trap="$(trap -p INT)"
if ! _demo_setup || [ -z "${MCPMOAT_DEMO_DIR:-}" ]; then
  [ -z "${MCPMOAT_DEMO_DIR:-}" ] || echo "setup.sh: setup failed; removed '$MCPMOAT_DEMO_DIR'" >&2
  _demo_reset
fi
[ -n "${ZSH_VERSION:-}" ] || eval "${_demo_trap:-trap - INT}"
unset -f _demo_setup
unset _demo_trap
[ -n "${MCPMOAT_DEMO_DIR:-}" ] || return 1
echo "mcpmoat demo folder: $MCPMOAT_DEMO_DIR"
echo "mcpmoat demo ready"
