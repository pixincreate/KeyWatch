#!/usr/bin/env bash

# Release Process
# 1. Update CHANGELOG.md with new version and changes
# 2. Run release script:
#   ```bash
#   ./scripts/release.sh 1.0.1
#   ```
# 3. Wait for GitHub Actions to:
#   - Build binaries for all platforms
#   - Create GitHub release
#   - Upload assets
# 4. Verify the release at: https://github.com/pixincreate/KeyWatch/releases

set -e

# Check if version is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

VERSION="$1"
CRATE_VERSION="version = \"$VERSION\""
DATE=$(date +%Y-%m-%d)

# Update version in workspace Cargo.toml
sed -i.bak "s/^version = .*/$CRATE_VERSION/" Cargo.toml
rm Cargo.toml.bak  # Clean up backup file

# Update CHANGELOG.md
sed -i.bak "s/## \[Unreleased\]/## [Unreleased]\n\n## [$VERSION] - $DATE/" CHANGELOG.md
rm CHANGELOG.md.bak  # Clean up backup file

# Show changes
echo "Changes made:"
echo "------------"
git diff

# Prompt for confirmation
read -p "Do you want to commit these changes and create tag v$VERSION? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # Commit changes
    git add Cargo.toml CHANGELOG.md
    git commit -m "chore: release version $VERSION"

    # Create and push tag
    git tag -a "v$VERSION" -m "KeyWatch v$VERSION"

    echo "Pushing changes..."
    git push origin main "v$VERSION"

    echo "KeyWatch release v$VERSION prepared and pushed!"
else
    # Revert changes if user doesn't confirm
    git checkout Cargo.toml CHANGELOG.md
    echo "KeyWatch release cancelled and changes reverted"
fi
