IPFire-Wall Documentation Maintenance Guide
========================================

Individual documentation chapters are stored as separate Markdown files (01_*.md to 05_*.md). 
To make it easier for reading and PDF export, a single CONSOLIDATED_REPORT.md is 
automatically generated from these files.

Usage:
------

1.  Edit the chapters:
    Modify any of the 01_... to 05_... markdown files.

2.  Update the consolidated report:
    Run the following command in this directory:

    make

    This will regenerate CONSOLIDATED_REPORT.md with the latest content 
    from all chapters.

3.  Cleanup:
    To remove the generated report:

    make clean

File Overviews:
---------------
- MASTER.md: The primary index and table of contents for the documentation.
- 01-05_*.md: Individual chapters focusing on specific technical areas.
- CONSOLIDATED_REPORT.md: The full, combined document (Auto-generated).
- Makefile: The build script that handles the concatenation.
