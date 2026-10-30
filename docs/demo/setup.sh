# shellcheck shell=bash
# Builds mcpmoat and the fixture servers, and writes a private demo HOME.
# Usage: source docs/demo/setup.sh   (from the repo root). See docs/demo/README.md.
#
# The file is sourced, so it never uses set -e: a failure must not close the
# caller's shell. Each step returns 1 instead.

# Other shells, such as dash, pass the guard below or cannot save the INT trap.
[ -n "${BASH_VERSION:-}${ZSH_VERSION:-}" ] || {
  echo "setup.sh: use bash or zsh" >&2
  # shellcheck disable=SC2317 # exit runs when the file runs as a script
  return 1 2>/dev/null || exit 1
}

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

if [ -n "${MCPMOAT_DEMO_DIR:-}" ] || [ -n "${MCPMOAT_DEMO_OLD_HOME+x}" ]; then
  echo "setup.sh: a demo is already active in '${MCPMOAT_DEMO_DIR:-}'; run demo_cleanup first" >&2
  return 1
fi

_mcpmoat_demo_write_config() { # $1 = rugpull args as a JSON array
  # >| overwrites the file also when the noclobber option is on.
  cat >|"$MCPMOAT_DEMO_DIR/home/.claude.json" <<JSON
{"mcpServers":{
 "notes":{"command":"$MCPMOAT_DEMO_DIR/poisoned"},
 "math":{"command":"$MCPMOAT_DEMO_DIR/shadowing"},
 "mailer":{"command":"$MCPMOAT_DEMO_DIR/mailer"},
 "clock":{"command":"$MCPMOAT_DEMO_DIR/rugpull","args":$1}
}}
JSON
}

# Removes the demo folder (if any), restores the saved variables and the
# caller's INT trap, and forgets the demo. Returns 1 if rm fails.
_mcpmoat_demo_reset() {
  local rc=0
  # rm first: if it is stopped, the demo stays active and can be cleaned again.
  if [ -n "${MCPMOAT_DEMO_DIR:-}" ] && ! rm -rf -- "$MCPMOAT_DEMO_DIR"; then
    echo "mcpmoat demo: could not remove the folder; remove it by hand: rm -rf -- '$MCPMOAT_DEMO_DIR'" >&2
    rc=1
  fi
  # Each saved value is "x" and the old value, or empty if the variable was unset.
  if [ -n "${MCPMOAT_DEMO_OLD_HOME+x}" ]; then
    case $MCPMOAT_DEMO_OLD_HOME in x*) export HOME="${MCPMOAT_DEMO_OLD_HOME#x}" ;; *) unset HOME ;; esac
    case $MCPMOAT_DEMO_OLD_PATH in x*) export PATH="${MCPMOAT_DEMO_OLD_PATH#x}" ;; *) unset PATH ;; esac
    case $MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME in
      x*) export XDG_CONFIG_HOME="${MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME#x}" ;;
      *) unset XDG_CONFIG_HOME ;;
    esac
    case $MCPMOAT_DEMO_OLD_XDG_CACHE_HOME in
      x*) export XDG_CACHE_HOME="${MCPMOAT_DEMO_OLD_XDG_CACHE_HOME#x}" ;;
      *) unset XDG_CACHE_HOME ;;
    esac
  fi
  # bash only: zsh restores the trap itself (local_traps in the setup).
  if [ -n "${_mcpmoat_demo_trap+x}" ]; then
    eval "${_mcpmoat_demo_trap:-trap - INT}"
    unset _mcpmoat_demo_trap
  fi
  unset MCPMOAT_DEMO_DIR MCPMOAT_DEMO_CACHE MCPMOAT_DEMO_OLD_HOME \
    MCPMOAT_DEMO_OLD_PATH MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME \
    MCPMOAT_DEMO_OLD_XDG_CACHE_HOME
  return "$rc"
}

demo_flip() {
  if [ -z "${MCPMOAT_DEMO_DIR:-}" ]; then
    echo "demo_flip: no active demo; source docs/demo/setup.sh first" >&2
    return 1
  fi
  _mcpmoat_demo_write_config '["-variant","injected"]'
}

demo_cleanup() {
  # Remove only a direct child "mcpmoat-demo.*" of the cache folder.
  local dir="${MCPMOAT_DEMO_DIR:-}" cache="${MCPMOAT_DEMO_CACHE:-}" rc name safe=
  name="${dir#"$cache"/}"
  case $name in
    "$dir" | */*) ;; # not below the cache folder, or not a direct child
    mcpmoat-demo.?*) [ -z "$cache" ] || safe=1 ;;
  esac
  # No folder: a stopped setup saved the variables only. Restore them.
  if [ -n "$dir" ] && [ -z "$safe" ]; then
    echo "demo_cleanup: refusing to remove '$dir'" >&2
    return 1
  fi
  _mcpmoat_demo_reset
  rc=$?
  unset -f _mcpmoat_demo_write_config _mcpmoat_demo_reset demo_flip demo_cleanup
  return "$rc"
}

_mcpmoat_demo_setup() {
  # C locale: in bash 3.2 the A-Za-z range below also matches letters like é.
  local LC_ALL=C home
  # zsh puts the caller's INT trap back when this function returns.
  [ -z "${ZSH_VERSION:-}" ] || setopt local_options local_traps
  if [ -n "${BASH_VERSION:-}" ]; then
    _mcpmoat_demo_trap="$(trap -p INT)"
    # The demo's own trap, left by a stopped setup, is not the caller's trap.
    case $_mcpmoat_demo_trap in *_mcpmoat_demo_reset*) _mcpmoat_demo_trap= ;; esac
  fi
  # Save all the caller's values in one step, before the trap and the folder.
  MCPMOAT_DEMO_OLD_HOME=${HOME+x$HOME} MCPMOAT_DEMO_OLD_PATH=${PATH+x$PATH} \
    MCPMOAT_DEMO_OLD_XDG_CONFIG_HOME=${XDG_CONFIG_HOME+x$XDG_CONFIG_HOME} \
    MCPMOAT_DEMO_OLD_XDG_CACHE_HOME=${XDG_CACHE_HOME+x$XDG_CACHE_HOME}
  # Ctrl-C: remove the half-built demo. bash runs this trap only when the
  # Ctrl-C comes during a builtin or a $(...) such as mktemp or find. An
  # external command such as go build gets the Ctrl-C alone and fails, and
  # its "|| return 1" cleans up. bash 3.2 and zsh drop the 1 of this return,
  # so the caller checks MCPMOAT_DEMO_DIR, which the reset unsets.
  trap '_mcpmoat_demo_reset; return 1' INT

  # An empty or relative HOME would give a root-level or relative cache folder.
  case ${HOME:-} in
    /?*) ;;
    *)
      echo "setup.sh: HOME must be an absolute path" >&2
      return 1
      ;;
  esac
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
  # Positive test: find prints the path only when no one else can write, so a
  # find that fails also refuses. -O follows a symlink and checks its target.
  if [ ! -O "$MCPMOAT_DEMO_CACHE" ] ||
    [ -z "$(find -H "$MCPMOAT_DEMO_CACHE" -maxdepth 0 ! -perm -020 ! -perm -002)" ]; then
    echo "setup.sh: '$MCPMOAT_DEMO_CACHE' must be yours and not writable by group or others; run: chmod go-w '$MCPMOAT_DEMO_CACHE'" >&2
    return 1
  fi

  MCPMOAT_DEMO_DIR="$(mktemp -d "$MCPMOAT_DEMO_CACHE/mcpmoat-demo.XXXXXX")" || return 1

  # Only mcpmoat goes on PATH. The config names the fixtures by absolute path.
  # -m 700 on home: with umask 002 a plain mkdir makes HOME group-writable,
  # and the run folder check would refuse it.
  mkdir "$MCPMOAT_DEMO_DIR/bin" || return 1
  mkdir -m 700 "$MCPMOAT_DEMO_DIR/home" || return 1
  # No loop here: in bash 5 a Ctrl-C that stops a command in a loop stops the
  # whole sourced file, and the cleanup does not run.
  go build -o "$MCPMOAT_DEMO_DIR/bin/mcpmoat" ./cmd/mcpmoat || return 1
  # With several packages, -o DIR/ writes each binary as DIR/<package folder name>.
  go build -o "$MCPMOAT_DEMO_DIR/" ./testdata/servers/poisoned ./testdata/servers/shadowing \
    ./testdata/servers/mailer ./testdata/servers/rugpull || return 1
  _mcpmoat_demo_write_config '[]' || return 1
  # A Ctrl-C in a nested call can return here with status 0.
  [ -n "${MCPMOAT_DEMO_DIR:-}" ] || return 1

  # One export: a trap cannot run between the four changes.
  home="$MCPMOAT_DEMO_DIR/home"
  export HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_CACHE_HOME="$home/.cache" \
    PATH="$MCPMOAT_DEMO_DIR/bin${PATH+:$PATH}"
  # bash: the demo is ready, so put the caller's INT trap back now.
  if [ -n "${_mcpmoat_demo_trap+x}" ]; then
    eval "${_mcpmoat_demo_trap:-trap - INT}"
    unset _mcpmoat_demo_trap
  fi
}

if ! _mcpmoat_demo_setup || [ -z "${MCPMOAT_DEMO_DIR:-}" ]; then
  [ -z "${MCPMOAT_DEMO_DIR:-}" ] || echo "setup.sh: setup failed; removing '$MCPMOAT_DEMO_DIR'" >&2
  _mcpmoat_demo_reset
  unset -f _mcpmoat_demo_write_config _mcpmoat_demo_reset demo_flip demo_cleanup \
    _mcpmoat_demo_setup
  return 1
fi
unset -f _mcpmoat_demo_setup
echo "mcpmoat demo folder: $MCPMOAT_DEMO_DIR"
echo "mcpmoat demo ready"
