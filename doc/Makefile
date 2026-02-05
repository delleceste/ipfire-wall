# Makefile for IPFire-Wall Documentation

REPORT = CONSOLIDATED_REPORT.md
CHAPTERS = 01_Refactoring_Optimization.md \
           02_Kernel_Architecture.md \
           03_Stateful_Connection_Management.md \
           04_Userspace_Application.md \
           05_Packet_Flow_Walkthroughs.md

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

clean:
	rm -f $(REPORT)

.PHONY: all clean
