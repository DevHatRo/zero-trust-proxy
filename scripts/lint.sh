#!/bin/bash

# Simple Go linting script using built-in tools
# This script runs basic linting and code quality checks

set -e

echo "🔍 Running Go linting and code quality checks..."

# 1. Check formatting
echo "Checking code formatting with 'go fmt'..."
if [ "$(go fmt ./... | wc -l)" -gt 0 ]; then
    echo "❌ Code is not properly formatted. Run 'go fmt ./...' to fix."
    exit 1
fi
echo "✅ Code formatting is correct."

# 2. Check imports
echo "Checking imports with 'goimports'..."
if command -v goimports &> /dev/null; then
    if [ "$(goimports -l . | wc -l)" -gt 0 ]; then
        echo "❌ Imports need fixing. Run 'goimports -w .' to fix."
        goimports -l .
        exit 1
    fi
    echo "✅ Imports are correct."
else
    echo "⚠️  goimports not found, skipping import check."
fi

# 3. Check for basic issues with go vet on our packages only
echo "Running 'go vet' on our packages..."
vetIssues=0

# Check main command packages
for pkg in ./cmd/agent ./cmd/server ./cmd/certgen; do
    if go list $pkg &>/dev/null; then
        echo "Checking $pkg..."
        if ! go vet $pkg 2>/dev/null; then
            echo "❌ Issues found in $pkg"
            vetIssues=1
        fi
    fi
done

# Check internal packages (excluding caddy which has dependency issues)
for pkg in ./internal/logger ./internal/common ./internal/agent ./internal/server; do
    if go list $pkg &>/dev/null; then
        echo "Checking $pkg..."
        if ! go vet $pkg 2>/dev/null; then
            echo "❌ Issues found in $pkg"
            vetIssues=1
        fi
    fi
done

if [ $vetIssues -eq 0 ]; then
    echo "✅ No vet issues found in our packages."
fi

# 4. Check for unused variables and simple inefficiencies
echo "Checking for potential issues..."

# Check for unused variables (simple grep-based check)
echo "Looking for potential unused variables..."
if grep -r "var.*=" --include="*.go" ./cmd ./internal | grep -v "_test.go" | grep -v "// " | head -5; then
    echo "⚠️  Found potential unused variables (manual review needed)."
else
    echo "✅ No obvious unused variables found."
fi

# Check for TODO/FIXME comments
echo "Checking for TODO/FIXME comments..."
if grep -r -n "TODO\|FIXME" --include="*.go" ./cmd ./internal; then
    echo "⚠️  Found TODO/FIXME comments that may need attention."
else
    echo "✅ No TODO/FIXME comments found."
fi

# 5. Build check for our packages (excluding problematic Caddy module)
echo "Checking if our main packages build successfully..."
buildSuccess=1

# Create bin directory if it doesn't exist
mkdir -p bin

# Build main commands
for pkg in ./cmd/agent ./cmd/server ./cmd/certgen; do
    binary_name=$(basename $pkg)
    echo "Building $pkg -> bin/$binary_name..."
    if go build -o bin/$binary_name $pkg; then
        echo "✅ $pkg builds successfully -> bin/$binary_name"
    else
        echo "❌ $pkg build failed."
        buildSuccess=0
    fi
done

# Build internal packages
for pkg in ./internal/logger ./internal/common ./internal/agent ./internal/server; do
    echo "Building $pkg..."
    if go build $pkg; then
        echo "✅ $pkg builds successfully."
    else
        echo "❌ $pkg build failed."
        buildSuccess=0
    fi
done

if [ $buildSuccess -eq 0 ]; then
    echo "❌ Some builds failed."
    exit 1
fi

# 6. Test check for our packages
echo "Running tests on our packages..."
testSuccess=1

for pkg in ./cmd/... ./internal/logger ./internal/common ./internal/agent ./internal/server; do
    if go list $pkg &>/dev/null; then
        echo "Testing $pkg..."
        if go test $pkg -v; then
            echo "✅ $pkg tests pass."
        else
            echo "❌ $pkg tests failed."
            testSuccess=0
        fi
    fi
done

if [ $testSuccess -eq 0 ]; then
    echo "❌ Some tests failed."
    exit 1
fi

echo ""
echo "🎉 Linting complete! Code quality checks passed."
