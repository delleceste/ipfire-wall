# IPFire-Wall Installation Guide

This document provides instructions for compiling and installing both the kernel module and the userspace application for IPFire-Wall.

## 1. Building the Kernel Module (`ipfi.ko`)

The firewall's core filtering engine and state tracking reside in the kernel module. To build it, you will need the Linux headers for your currently running kernel.

Navigate to the `kernel/` directory and run:

```bash
cd kernel/
make
```

### Bucket Size Configuration
You can customize the size of the internal hash tables during compilation by providing bucket size options to `make`. For example, adjusting the `STATE_HASH_BITS` or related constants allows you to optimize the memory footprint and collision rate based on your expected network load.

The resulting module is `ipfi.ko`, which must be loaded by the `sysadmin` (or automatically via the system service) before starting the userspace application.

## 2. Building the Userspace Application (`ipfire`)

The userspace application is responsible for communicating with the kernel via Netlink sockets, providing the CLI interface for administrators and unprivileged users. It is built using CMake.

Navigate to the `ipfi/` subdirectory and run:

```bash
cd ipfi/
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr
sudo cmake --build build --target install
```

*Note: The `CMAKE_INSTALL_PREFIX` dictates where the binaries (`/bin/`), configuration files (`/etc/ipfire/`), and shared language assets (`/share/ipfire/`) will be installed. If omitted, it defaults to `/usr/local`.*

## 3. Main Command Line Switches

Once installed, the `ipfire` application can be controlled via several command-line flags. Here are the most important ones:

### Daemon & Service Operations (Root Only)
- `-load`, `-rc`: Load all rules from configuration files (`/etc/ipfire/`) and run in the background.
- `-daemon`: Run the application as a background daemon without flushing console output.
- `-quiet_daemon`: Run as a background daemon and redirect standard output/error to `/dev/null`.
- `-flush`: Flush all rules from the kernel and exit immediately.
- `-rmmod`: Unload the `ipfi` kernel module upon exit.

### User Permissions
- `-user`: Allow normal unprivileged users to define their own rules and interact with the firewall (Root only).
- `-nouser`: Restrict all firewall operations to the Root user.

### Advanced Features & Tuning
- `-kloglevel <0-7>`: Set the kernel-space log level (0=Emergency, 7=Debug).
- `-loguser <0-7>`: Set the userspace interface log level.
- `-allstate`: Enable stateful tracking for ALL traffic, regardless of rule flags.

When running as a service, the standard initialization command is `ipfire -rc -user`, establishing root security baseline rules while allowing users to connect and manage their own local traffic securely.
