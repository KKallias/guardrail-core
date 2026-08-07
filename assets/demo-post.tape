# VHS tape - the longer clip for a Reddit / Discord / X post.
#
#   brew install vhs
#   cd <repo root> && vhs assets/demo-post.tape
#
# Uses --step so each section lands as its own beat, with enough dwell
# time to actually read the BLOCK reasons. Bigger font than the README
# version, because this gets viewed in a feed on a phone.
#
# The demo pauses on input() before each of the three sections, so each
# `Enter` below advances exactly one section.

Output assets/demo-post.gif

# Sized to the demo's output (89 columns x 47 lines) plus the --step
# prompts, at a font big enough to read on a phone in a feed.
Set Shell "bash"
Set FontSize 22
Set Width 1330
Set Height 1450
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Hide
Type "clear"
Enter
Show

Sleep 800ms
Type "python examples/unified_demo.py --step"
Sleep 500ms
Enter

# Header + the first [enter to continue] prompt.
Sleep 2s
Enter

# Section 1: x402. Three ALLOWs, the spend-cap BLOCK, the allowlist
# BLOCK. This is the money shot - give it room.
Sleep 7s
Enter

# Section 2: PII redaction. Raw message in, redacted message received.
Sleep 6s
Enter

# Section 3: the audit trail with the namespaced rule names.
Sleep 6s
