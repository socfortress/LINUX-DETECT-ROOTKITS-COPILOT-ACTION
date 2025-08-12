#!/bin/bash

# Set strict error handling
set -e

# Get parameters from environment variables or defaults
SCRIPT_NAME=${SCRIPT_NAME:-""}
VERSION=${VERSION:-""}
REPOSITORY=${GITHUB_REPOSITORY:-""}
COMMIT_SHA=${GITHUB_SHA:-""}

# Print header
echo -e "\e[32m🚀 Building release for $SCRIPT_NAME $VERSION\e[0m"

# Determine if we're running from scripts/ directory or repository root
if [ -d "../.github" ] && [ -f "../${SCRIPT_NAME}.sh" ]; then
    # Running from scripts/ directory
    release_dir="../release"
    source_script="../${SCRIPT_NAME}.sh"
elif [ -d ".github" ] && [ -f "${SCRIPT_NAME}.sh" ]; then
    # Running from repository root
    release_dir="./release"
    source_script="./${SCRIPT_NAME}.sh"
else
    echo -e "\e[31mError: Cannot locate source script or determine working directory\e[0m"
    echo -e "\e[33mMake sure the script is in the repository root directory\e[0m"
    echo -e "\e[33mChecking for: ${SCRIPT_NAME}.sh\e[0m"
    echo -e "\e[33mCurrent directory: $(pwd)\e[0m"
    echo -e "\e[33mDirectory contents:\e[0m"
    ls -la
    exit 1
fi

# Create release directory
rm -rf "$release_dir"
mkdir -p "$release_dir"

# Validate source script exists
if [ ! -f "$source_script" ]; then
    echo -e "\e[31mError: Source script not found: $source_script\e[0m"
    echo -e "\e[33mMake sure the script is in the repository root directory\e[0m"
    exit 1
fi

# Read the original script
script_content=$(cat "$source_script")
build_date=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Create metadata header
header="#!/bin/bash
#
# SYNOPSIS
#     $SCRIPT_NAME - Linux Active Response Script $VERSION
#
# DESCRIPTION
#     Production release of $SCRIPT_NAME for active response automation.
#
# METADATA
#     Repository: https://github.com/$REPOSITORY
#     Release Version: $VERSION
#     Build Date: $build_date
#     Commit SHA: $COMMIT_SHA
#
# NOTES
#     This script is part of the Linux Active Response framework.
#     For documentation and updates, visit: https://github.com/$REPOSITORY
#
"

# Create production scripts
production_script="${header}${script_content}"

# Save versioned script
versioned_path="${release_dir}/${SCRIPT_NAME}-${VERSION}.sh"
echo "$production_script" > "$versioned_path"
chmod +x "$versioned_path"

# Save generic script
generic_path="${release_dir}/${SCRIPT_NAME}.sh"
echo "$production_script" > "$generic_path"
chmod +x "$generic_path"

echo "✅ Production scripts created:"
echo "  - $versioned_path"
echo "  - $generic_path"

# Generate checksums
checksum_file="${release_dir}/checksums.txt"
rm -f "$checksum_file"
for script in "${release_dir}"/*.sh; do
    (cd "$(dirname "$script")" && sha256sum "$(basename "$script")") >> "$checksum_file"
done
echo "✅ Checksums generated"

# Create installation script
cat > "${release_dir}/install.sh" << EOL
#!/bin/bash
#
# SYNOPSIS
#     Automated installer for $SCRIPT_NAME $VERSION
#
# DESCRIPTION
#     Downloads and installs the $SCRIPT_NAME bash script from GitHub releases.
#
# PARAMETERS
#     -p, --path        Installation path (default: current directory)
#     -v, --verify      Verify script integrity (default: true)
#     -h, --help        Show this help message

# Default parameters
INSTALL_PATH="."
VERIFY=true

# Parse arguments
while [[ \$# -gt 0 ]]; do
    case \$1 in
        -p|--path) INSTALL_PATH="\$2"; shift 2 ;;
        -v|--verify) VERIFY=\$2; shift 2 ;;
        -h|--help) echo "Usage: \$0 [-p|--path <path>] [-v|--verify true|false]"; exit 0 ;;
        *) echo "Unknown parameter: \$1"; exit 1 ;;
    esac
done

# Release configuration
REPO_URL="https://github.com/$REPOSITORY"
VERSION="$VERSION"
SCRIPT_NAME="$SCRIPT_NAME"
BASE_URL="\$REPO_URL/releases/download/\$VERSION"
SCRIPT_URL="\$BASE_URL/\$SCRIPT_NAME.sh"
CHECKSUM_URL="\$BASE_URL/checksums.txt"

echo -e "\e[32m🚀 Installing \$SCRIPT_NAME \$VERSION...\e[0m"
echo "📍 Install Path: \$INSTALL_PATH"

# Create install directory if needed
mkdir -p "\$INSTALL_PATH"
echo "📁 Created directory: \$INSTALL_PATH"

# Download script
script_path="\$INSTALL_PATH/\$SCRIPT_NAME.sh"
echo "⬇️  Downloading script..."
if ! curl -sSL "\$SCRIPT_URL" -o "\$script_path"; then
    echo -e "\e[31m❌ Failed to download script\e[0m"
    exit 1
fi
chmod +x "\$script_path"
echo "✅ Script downloaded: \$script_path"

# Verify integrity if requested
if [ "\$VERIFY" = true ]; then
    echo "🔍 Verifying script integrity..."
    if ! checksum_content=\$(curl -sSL "\$CHECKSUM_URL"); then
        echo -e "\e[33m⚠️  Could not download checksums for verification\e[0m"
    else
        expected_hash=\$(echo "\$checksum_content" | grep "\$SCRIPT_NAME.sh" | cut -d' ' -f1)
        actual_hash=\$(cd "\$INSTALL_PATH" && sha256sum "\$SCRIPT_NAME.sh" | cut -d' ' -f1)
        
        if [ "\$actual_hash" = "\$expected_hash" ]; then
            echo "✅ Script integrity verified"
        else
            echo -e "\e[31m❌ Script integrity check failed!\e[0m"
            echo "Expected: \$expected_hash"
            echo "Got: \$actual_hash"
            exit 1
        fi
    fi
fi

echo
echo -e "\e[32m🎉 Installation completed successfully!\e[0m"
echo "📄 Script location: \$script_path"
echo
echo "📖 Usage examples:"
echo "   ./\$SCRIPT_NAME.sh"
echo "   # Or with parameters:"
echo "   ./\$SCRIPT_NAME.sh --timeout 600"
echo
echo "🔗 Documentation: \$REPO_URL"
EOL

chmod +x "${release_dir}/install.sh"
echo "✅ Installation script created"

# Create release documentation
cat > "${release_dir}/README.md" << EOL
# $SCRIPT_NAME Release $VERSION

This release contains production-ready bash scripts for active response automation.

## Files

- **$SCRIPT_NAME.sh** - Main bash script (generic name)
- **$SCRIPT_NAME-$VERSION.sh** - Versioned bash script
- **install.sh** - Automated installation script
- **checksums.txt** - SHA256 checksums for integrity verification
- **README.md** - This file

## Quick Installation

### Option 1: Automated Installation (Recommended)
\`\`\`bash
# Download and run installer
curl -sSL "https://github.com/$REPOSITORY/releases/download/$VERSION/install.sh" -o install.sh
chmod +x install.sh
./install.sh
\`\`\`

### Option 2: Manual Download
\`\`\`bash
# Download script directly
curl -sSL "https://github.com/$REPOSITORY/releases/download/$VERSION/$SCRIPT_NAME.sh" -o "$SCRIPT_NAME.sh"
chmod +x "$SCRIPT_NAME.sh"
\`\`\`

## Usage

\`\`\`bash
# Basic execution
./$SCRIPT_NAME.sh

# With custom parameters
./$SCRIPT_NAME.sh --timeout 600 --log-path "/var/log/my-script.log"
\`\`\`

## Security Considerations

1. **Script Verification**: Always verify script integrity using the provided checksums
2. **Permissions**: Ensure the script has appropriate execution permissions
3. **Network Security**: Consider network policies when downloading scripts in production environments

## Integrity Verification

Verify the downloaded script using sha256sum:

\`\`\`bash
# Get file hash
sha256sum "$SCRIPT_NAME.sh"

# Compare with expected hash from checksums.txt
# Expected hash: [hash will be shown in checksums.txt]
\`\`\`

## Support

- **Repository**: https://github.com/$REPOSITORY
- **Issues**: https://github.com/$REPOSITORY/issues
- **Documentation**: See repository README for detailed documentation

## Build Information

- **Version**: $VERSION
- **Build Date**: $build_date
- **Commit SHA**: $COMMIT_SHA
- **Generated by**: GitHub Actions

## License

This script is provided as-is for security automation and incident response purposes.
EOL

echo "✅ Release documentation created"

# List all artifacts
echo
echo -e "\e[33m📦 Release artifacts:\e[0m"
for file in "${release_dir}"/*; do
    size=$(du -h "$file" | cut -f1)
    echo -e "\e[36m  📄 $(basename "$file") ($size)\e[0m"
done

echo
echo -e "\e[32m✅ Release build completed successfully!\e[0m"
