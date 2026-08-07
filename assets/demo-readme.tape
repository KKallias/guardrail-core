# VHS tape - compact GIF for the README.
#
#   brew install vhs
#   cd <repo root> && vhs assets/demo-readme.tape
#
# Runs the demo without --step: no pauses, ~4s, small enough to sit at
# the top of a README. Regenerate this whenever the demo output changes.

Output assets/demo.gif

# Sized to the demo's actual output: 89 columns x 47 lines, measured.
# Keep these in sync if the demo grows - a wrapped line ruins the GIF.
Set Shell "bash"
Set FontSize 18
Set Width 1120
Set Height 1150
Set Padding 25
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

# Start on a clean screen - no leftover prompt from the recording setup.
Hide
Type "clear"
Enter
Show

Sleep 500ms
Type "python examples/unified_demo.py"
Sleep 400ms
Enter

# The demo itself takes ~3s (two 1s pauses between sections).
Sleep 6s

# Hold on the final audit trail so the rule names are readable.
Sleep 3s
