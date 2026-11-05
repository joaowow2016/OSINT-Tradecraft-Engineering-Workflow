#!/usr/bin/env bash
# ==============================================================================
# OPSEC-Safe GitHub Repository Push Helper for SOVEREIGN-WATCH (efotw-osint)
# Usage:
#   Option A (GitHub CLI - Recommended locally):
#     gh auth login
#     gh repo create sovereign-watch-efotw --public --source=. --remote=origin --push
#
#   Option B (Standard SSH or HTTPS Remote):
#     ./scripts/push_to_github.sh https://github.com/<USERNAME>/<REPO>.git
#
#   Option C (Ephemeral Fine-Grained Token in Environment — never saved to .git/config):
#     GITHUB_USER="<USERNAME>" GITHUB_TOKEN="<FINE_GRAINED_PAT>" \
#       ./scripts/push_to_github.sh https://github.com/<USERNAME>/<REPO>.git
# ==============================================================================

set -euo pipefail

REPO_URL="${1:-}"
BRANCH="${2:-main}"

if [[ -z "${REPO_URL}" ]]; then
  echo "Usage: $0 <https://github.com/USERNAME/REPO.git | git@github.com:USERNAME/REPO.git> [branch]"
  exit 1
fi

# Ensure git repository is initialized on target branch
if [[ ! -d .git ]]; then
  git init -b "${BRANCH}"
fi

git checkout -B "${BRANCH}"

# Configure clean remote URL (never embed tokens inside .git/config!)
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "${REPO_URL}"
else
  git remote add origin "${REPO_URL}"
fi

if [[ -n "${GITHUB_TOKEN:-}" && "${REPO_URL}" == https://github.com/* ]]; then
  echo "[OPSEC] Pushing via ephemeral HTTP Authorization header (token NOT written to .git/config)..."
  AUTH_B64="$(printf '%s:%s' "${GITHUB_USER:-x-access-token}" "${GITHUB_TOKEN}" | base64 | tr -d '\n')"
  git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${AUTH_B64}" push -u origin "${BRANCH}"
else
  echo "[GIT] Pushing branch '${BRANCH}' to ${REPO_URL}..."
  git push -u origin "${BRANCH}"
fi

echo "✓ Successfully pushed SOVEREIGN-WATCH to ${REPO_URL} (${BRANCH})"
