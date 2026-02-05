# IPFire-Wall Project: Master Documentation

Welcome to the comprehensive technical documentation for the IPFire-Wall kernel module and userspace suite. This document serves as a consolidated guide covering architectural details, recent refactoring achievements, and operational usage.

## Index of Chapters

1. **[Refactoring & Optimization](01_Refactoring_Optimization.md)**  
   *Modular organization, Per-CPU statistics, and Netlink simplifications.*

2. **[Kernel Module Architecture](02_Kernel_Architecture.md)**  
   *Netfilter integration, rule hierarchy, and block/allow list logic.*

3. **[Stateful Connection Management](03_Stateful_Connection_Management.md)**  
   *Fast-path hashing, TCP/UDP state machines, and dynamic FTP support.*

4. **[Userspace Application (ipfire)](04_Userspace_Application.md)**  
   *Command line interface, configuration, and monitoring.*

5. **[Packet Flow Walkthroughs](05_Packet_Flow_Walkthroughs.md)**  
   *Step-by-step analysis of NAT, State matching, and Forwarding.*

6. **[Detailed Packet Flows](06_Detailed_Packet_Flows.md)**  
   *Comprehensive walkthroughs with Mermaid diagrams for HTTP, FTP, and SSH.*

7. **[State Machine Deep Dive](07_State_Machine_Deep_Dive.md)**  
   *In-depth analysis of TCP/UDP state transitions and GUESS states.*

8. **[NAT Flow Analysis](08_NAT_Flow_Analysis.md)**  
   *Detailed SNAT, Masquerade, and DNAT flows with checksum verification.*

9. **[Developer API Guide](09_Developer_API_Guide.md)**  
   *Internal kernel interfaces, shared structures, and Netlink protocols.*

---

## How to use this documentation
- **For Developers**: Start with [Chapter 1](01_Refactoring_Optimization.md) and [Chapter 2](02_Kernel_Architecture.md) to understand the modern structure and hook flow.
- **For Administrators**: Refer to [Chapter 4](04_Userspace_Application.md) for command examples and configuration details.
- **For PDF Export**: This set of files is designed for easy conversion via tools like Pandoc or Markdown export extensions.

## Maintaining the Reports
The consolidated report can be kept in sync using the provided `Makefile` in this directory:
1. **Modify Chapters**: Edit individual `.md` files (01..05).
2. **Sync**: Run `make` inside the `doc/` directory to regenerate `CONSOLIDATED_REPORT.md`.
3. **Clean**: Run `make clean` to remove the generated report.

---
*Document Version: 2.0 (Refactored)*
