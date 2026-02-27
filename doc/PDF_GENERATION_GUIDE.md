# IPFire-Wall PDF Generation Guide

This guide explains how to generate the consolidated technical documentation for the IPFire-Wall project, including rich syntax-highlighted source code and rendered Mermaid diagrams.

## Prerequisites

To run the generation pipeline, ensure your system has the following installed:

| Dependency | Purpose |
|------------|---------|
| **Node.js / npm** | Renders Mermaid diagrams as SVGs and converts Markdown to PDF via Puppeteer. |
| **Python 3** | Aggregates kernel source code and applies high-fidelity syntax highlighting. |
| **Pandoc** | Merges individual `.md` chapters into a single consolidated report. |
| **Make** | Orchestrates the build process. |

### Note for Arch Linux Users
The pipeline uses **Node.js** (Puppeteer/Chromium) for PDF rendering instead of `wkhtmltopdf` or LaTeX engines, which avoids compatibility issues with legacy libraries on Arch.

## Quick Start

1. Navigate to the `doc/` directory:
   ```bash
   cd doc/
   ```

2. Run the automated generation script:
   ```bash
   ./generate_pdf.sh
   ```

The script will automatically set up a local Python virtual environment (`.venv`) and a Node.js `node_modules` folder to handle its internal dependencies.

## Output

The final document will be created at:
`doc/CONSOLIDATED_REPORT.pdf`

## Customizing Syntax Highlighting

The source code highlighting is managed by **Pygments** inside [scripts/build_appendix.py](scripts/build_appendix.py).

If you wish to change the color scheme:
1. Open `scripts/build_appendix.py`.
2. Locate the `CUSTOM_CSS` variable.
3. Modify the CSS classes (e.g., `.nf` for functions, `.nv` for variables) with your preferred hex colors.

## Troubleshooting

- **Puppeteer/Chromium issues**: If the PDF generation fails, ensure you have the necessary libraries for Chromium to run (on Arch: `nss`, `atk`, `at-spi2-atk`, `cups`, `libxcomposite`, `libxdamage`, `libxrandr`, `pango`, `cairo`, `asound`).
- **Font errors**: If characters look distorted, ensure standard Unicode fonts are installed on your system.
