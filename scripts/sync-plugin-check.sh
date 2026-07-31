#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:-2.0.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STANDARDS_DIR="${REPO_ROOT}/standards"
ARCHIVE="/tmp/plugin-check-${VERSION}.zip"
EXTRACT_DIR="/tmp/plugin-check-${VERSION}"

curl -fsSL "https://github.com/WordPress/plugin-check/archive/refs/tags/${VERSION}.zip" -o "${ARCHIVE}"
rm -rf "${EXTRACT_DIR}"
unzip -q "${ARCHIVE}" -d /tmp
mv "/tmp/plugin-check-${VERSION}" "${EXTRACT_DIR}"

rm -rf \
    "${STANDARDS_DIR}/PluginCheck/Sniffs" \
    "${STANDARDS_DIR}/PluginCheck/Helpers" \
    "${STANDARDS_DIR}/plugin-check-rulesets/plugin-review.xml" \
    "${STANDARDS_DIR}/plugin-check-rulesets/plugin-check.ruleset.xml"

cp -R "${EXTRACT_DIR}/phpcs-sniffs/PluginCheck/Sniffs" "${STANDARDS_DIR}/PluginCheck/"
cp -R "${EXTRACT_DIR}/phpcs-sniffs/PluginCheck/Helpers" "${STANDARDS_DIR}/PluginCheck/"
cp "${EXTRACT_DIR}/phpcs-sniffs/PluginCheck/ruleset.xml" "${STANDARDS_DIR}/PluginCheck/ruleset.xml"
cp "${EXTRACT_DIR}/phpcs-rulesets/plugin-review.xml" "${STANDARDS_DIR}/plugin-check-rulesets/"
cp "${EXTRACT_DIR}/phpcs-rulesets/plugin-check.ruleset.xml" "${STANDARDS_DIR}/plugin-check-rulesets/"

cat > "${STANDARDS_DIR}/plugin-check-rulesets/SOURCE.md" <<EOF
# WordPress Plugin Check PHPCS rules

Vendored from [WordPress/plugin-check](https://github.com/WordPress/plugin-check) for local org-review linting.

| Field | Value |
|-------|-------|
| Upstream version | ${VERSION} |
| Upstream tag | \`${VERSION}\` |
| Source paths | \`phpcs-rulesets/\`, \`phpcs-sniffs/PluginCheck/\` |
| License | GPL-2.0-or-later |

Refresh with:

\`\`\`bash
./scripts/sync-plugin-check.sh [version]
\`\`\`

Default version is the tag recorded above.
EOF

echo "Synced Plugin Check PHPCS assets from tag ${VERSION}."
