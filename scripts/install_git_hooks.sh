#!/usr/bin/env bash
# Enable the versioned git hooks for THIS clone only (sets core.hooksPath; reversible with
# `git config --unset core.hooksPath`). Nothing global is touched.
set -eu
root=$(git rev-parse --show-toplevel)
chmod +x "$root/scripts/hooks/pre-push"
git -C "$root" config core.hooksPath scripts/hooks
echo "hooks enabled: core.hooksPath=scripts/hooks (undo: git config --unset core.hooksPath)"
