#!/bin/bash

# IPFire-Wall PDF Generation Script
# This script handles dependencies, environment setup, and the build pipeline.

set -e

echo "===================================================="
echo "    IPFire-Wall: Documentation Generation Utility    "
echo "===================================================="
echo ""
echo "Checking System Dependencies..."

# 1. Dependency Check
MISSING_DEPS=()
command -v node >/dev/null 2>&1 || MISSING_DEPS+=("node/npm")
command -v python3 >/dev/null 2>&1 || MISSING_DEPS+=("python3")
command -v pandoc >/dev/null 2>&1 || MISSING_DEPS+=("pandoc")

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo "ERROR: Missing system dependencies: ${MISSING_DEPS[*]}"
    echo "Please install them via your package manager (e.g., pacman -S nodejs npm python pandoc)"
    exit 1
fi

echo "  [✓] node/npm found"
echo "  [✓] python3 found"
echo "  [✓] pandoc found"
echo ""

# 2. Workspace Setup
DOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "$DOC_DIR/../kernel" && pwd)"

echo "Setting up environments in $DOC_DIR..."

cd "$DOC_DIR"

# Python Virtual Env for Pygments
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "Installing Python dependencies (Pygments)..."
pip install -q Pygments

# Node dependencies for Mermaid and PDF
if [ ! -d "node_modules" ]; then
    echo "Installing Node dependencies (mermaid-cli, md-to-pdf)..."
    npm install -q @mermaid-js/mermaid-cli md-to-pdf
fi

echo ""
echo "===================================================="
echo "    Executing Build Pipeline                       "
echo "===================================================="

# Step A: Generate Appendix
echo "[1/4] Generating Source Code Appendix with Semantic Highlighting..."
python3 scripts/build_appendix.py

# Step B: Consolidate Documentation
echo "[2/4] Merging Markdown chapters..."
make CONSOLIDATED_REPORT.md

# Step C: Render Mermaid Charts and Generate PDF
echo "[3/4] Converting to PDF (Node.js/Puppeteer)..."
export PATH="$DOC_DIR/node_modules/.bin:$PATH"
# Using the make target we established earlier
make pdf-node

# Step D: Cleanup
echo "[4/4] Finalizing document..."
echo ""
ls -lh CONSOLIDATED_REPORT.pdf

echo ""
echo "Success! The document is ready at: $DOC_DIR/CONSOLIDATED_REPORT.pdf"
echo "===================================================="
