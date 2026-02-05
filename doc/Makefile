# Makefile for IPFire-Wall Documentation

REPORT = CONSOLIDATED_REPORT.md
PDF = CONSOLIDATED_REPORT.pdf
CHAPTERS = 01_Refactoring_Optimization.md \
           02_Kernel_Architecture.md \
           03_Stateful_Connection_Management.md \
           04_Userspace_Application.md \
           05_Packet_Flow_Walkthroughs.md \
           06_Detailed_Packet_Flows.md \
           07_State_Machine_Deep_Dive.md \
           08_NAT_Flow_Analysis.md

all: $(REPORT)

$(REPORT): $(CHAPTERS)
	@echo "Generating $(REPORT)..."
	@echo "# IPFire-Wall: Consolidated Project Report" > $(REPORT)
	@echo "" >> $(REPORT)
	@echo "*Generated on: $$(date)*" >> $(REPORT)
	@echo "" >> $(REPORT)
	@for f in $(CHAPTERS); do \
		echo "Adding $$f..."; \
		cat $$f >> $(REPORT); \
		echo "" >> $(REPORT); \
		echo "---" >> $(REPORT); \
		echo "" >> $(REPORT); \
	done
	@echo "Done."

# PDF conversion using Pandoc + LaTeX (default)
pdf: $(REPORT)
	@echo "Converting to PDF using Pandoc + LaTeX..."
	@if command -v pandoc >/dev/null 2>&1; then \
		ENGINE=""; \
		if command -v pdflatex >/dev/null 2>&1; then \
			ENGINE="pdflatex"; \
		elif command -v xelatex >/dev/null 2>&1; then \
			ENGINE="xelatex"; \
		elif command -v lualatex >/dev/null 2>&1; then \
			ENGINE="lualatex"; \
		fi; \
		if [ -n "$$ENGINE" ]; then \
			echo "Using PDF engine: $$ENGINE"; \
			pandoc $(REPORT) -o $(PDF) \
				--pdf-engine=$$ENGINE \
				--toc \
				--toc-depth=3 \
				-V geometry:margin=1in \
				-V linkcolor:blue \
				-V fontsize=11pt 2>&1; \
			if [ -f $(PDF) ]; then \
				echo "PDF generated successfully: $(PDF)"; \
			else \
				echo "Error: LaTeX packages missing."; \
				echo "Install with: sudo apt install texlive-latex-extra"; \
				echo "Or use 'make pdf-html' for HTML-based conversion (no LaTeX required)"; \
				exit 1; \
			fi; \
		else \
			echo "No LaTeX engine found. Install with: sudo apt install texlive-latex-base"; \
			exit 1; \
		fi; \
	else \
		echo "Error: pandoc not found. Install with: sudo apt install pandoc"; \
		exit 1; \
	fi

# Alternative: PDF conversion using wkhtmltopdf (no LaTeX required)
pdf-html: $(REPORT)
	@echo "Converting to PDF using wkhtmltopdf..."
	@if command -v wkhtmltopdf >/dev/null 2>&1; then \
		wkhtmltopdf --enable-local-file-access $(REPORT) $(PDF) 2>/dev/null; \
		if [ -f $(PDF) ]; then \
			echo "PDF generated successfully: $(PDF)"; \
		else \
			echo "Error: PDF generation failed"; \
			exit 1; \
		fi; \
	else \
		echo "Error: wkhtmltopdf not found."; \
		echo "Install with: sudo apt install wkhtmltopdf"; \
		exit 1; \
	fi

clean:
	rm -f $(REPORT) $(PDF)

.PHONY: all pdf pdf-html clean
