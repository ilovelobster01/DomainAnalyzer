#!/usr/bin/env bash
set -euo pipefail

# Initialize a local git repo and set remote origin to your GitHub repo.
# You will push with your SSH key after this setup.

REPO_URL=${1:-git@github.com:ilovelobster01/DomainAnalyzer.git}

if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Please install git and rerun: bash git_setup.sh" >&2
  exit 1
fi

if [ ! -d .git ]; then
  git init
fi

git add .
if ! git diff --cached --quiet; then
  git commit -m "Initial project scaffold"
fi

if git remote get-url origin >/dev/null 2>&1; then
  echo "Remote 'origin' already set to: $(git remote get-url origin)"
else
  git remote add origin "$REPO_URL"
  echo "Set remote 'origin' to $REPO_URL"
fi

echo "\nNext steps:"
echo "  1) Ensure your SSH key is added to your GitHub account."
echo "  2) Push: git push -u origin master  (or main, depending on your default branch)"
