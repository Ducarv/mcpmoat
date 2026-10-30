# Regenerate: vhs docs/demo/demo.tape   (run from the repo root)
Output docs/demo/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 16
Set TypingSpeed 25ms
Set Theme "Dracula"
# A cold Go build cache can take a while.
Set WaitTimeout 120s

Hide
Type "source docs/demo/setup.sh" Enter
Wait+Screen /mcpmoat demo ready/
Type "clear" Enter
Sleep 300ms
Show

Type "# 1. First scan: pins every tool, flags tool poisoning (T1) and shadowing (T3)" Enter
Sleep 500ms
Type "mcpmoat scan --no-color 2>&1 | grep -E 'pinned|MOAT-|Server:' | sed -n '1,12p;/pinned/p'" Enter
Wait
Sleep 6s

Hide
Type "clear && demo_flip" Enter
Sleep 300ms
Show

Type "# 2. The clock server changes a tool after it was pinned (rug pull, T2)" Enter
Sleep 500ms
Type "mcpmoat scan --no-color | sed -n '/MOAT-T2/,/Risk:/p;/^[-+]desc/p' | fold -sw 110" Enter
Wait
Sleep 7s

Hide
Type "demo_cleanup" Enter
Sleep 500ms
