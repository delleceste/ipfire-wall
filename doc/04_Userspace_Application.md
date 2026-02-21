# Chapter 4: Userspace Application (ipfire)

The `ipfire` utility is the primary administrative tool for interacting with the kernel-space firewall module.

## 4.1. Core Usage & CLI Flags
The application communicates with the kernel via Netlink sockets using the `IPFI_CONTROL` and `IPFI_DATA` protocols.

### General Options
| Flag | Description |
|------|-------------|
| `-h, --help` | Show the help message and exit. |
| `-quiet` | Do not print packets to the console. |
| `-daemon` | Run the application as a background daemon. |
| `-quiet_daemon` | Run as a background daemon and redirect standard output/error to `/dev/null`. |
| `-lang <file>` | Specify a language file (detected automatically by default). |

### Initialization & Cleanup (Root Only)
| Flag | Description |
|------|-------------|
| `-load, -rc` | Load all rules from configuration files and run in the background. |
| `-flush` | Flush all rules from the kernel and exit immediately. |
| `-noflush` | Prevent the automatic flushing of rules when the userspace process exits. |
| `-rmmod` | Unload the `ipfire` kernel module upon exit. |
| `-clearlog` | Truncate the log file at startup. |

### Configuration Paths
| Flag | Description |
|------|-------------|
| `-allowed <file>` | Override the path for the permission rules file. |
| `-blacklist <file>` | Override the path for the denial rules file. |
| `-blacksites <file>`| Override the path for the blocked sites list. |
| `-translation <file>`| Override the path for the NAT rules file. |
| `-logfile <file>` | Override the path for the system log file (Root only). |

### Advanced Features & Tuning
| Flag | Description |
|------|-------------|
| `-kloglevel <0-7>` | Set the kernel-space log level (0=Emergency, 7=Debug). |
| `-loguser <0-7>` | Set the userspace interface log level. |
| `-log <0-7>` | Set the logging level for the file-based logger. |
| `-dns <seconds>` | Enable the DNS resolver with a specific refresh interval. |
| `-nodns` | Disable the background DNS resolver. |
| `-services` | Enable resolution of port numbers to service names (via `/etc/services`). |
| `-noservices` | Disable port-to-service name resolution. |
| `-allstate` | Enable stateful tracking for ALL traffic, regardless of rule flags. |
| `-mailer <V> <U>` | Send email summaries every `<V>` units of `<U>` (sec, min, hour, days). |
| `-user` | Allow normal unprivileged users to define their own rules and interact with the firewall (Root only). |
| `-nouser` | Restrict all firewall operations to the Root user. |

## 4.2. Configuration Files
The application behavior can be customized via config files. For the root user, these are located in `/etc/ipfire/`. For normal users, they are in `~/.IPFIRE/`.

- `allowed`: List of rules to be automatically loaded on startup.
- `options`: Global configuration file (compatible with IqFIREwall) using a simple `KEY=VALUE` format.
- Shared assets (default rules, documentation, help) are stored in `/usr/share/ipfire/`.

## 4.3. Interpreting Statistics
The `-s` (Statistics) output is divided into three sections:
1. **Userspace Stats**: Counts of packets actually received and displayed by the tool. Useful for auditing.
2. **Kernel Stats**: High-level counters for `INPUT`, `OUTPUT`, `FORWARD`, and `POST-ROUTING`.
3. **Transmission Health**: Specifically reports `total_lost` (packets the kernel tried to log but couldn't due to buffer pressure).

## 4.4. Logging and Real-time Monitoring
When running, `ipfire` can act as a listener, printing headers for every packet matched by a rule with the `NOTIFY` flag. These logs include:
- **Verdict Markers**:
  - `<span style="color:violet">[?X]</span>`: No matching rule was found (packet fallback to default policy).
  - `<span style="color:green">[OK N]</span>`: Packet accepted by permission rule number `N`.
  - `<span style="color:red">[X M]</span>`: Packet dropped by denial rule number `M`.
- Timestamp and user ID.
- Hook location and verdict (`ACCEPT`/`DROP`).
- Detailed IP/TCP/UDP header information.
## 4.5. Logging Deduplication & Technical Bounds
To prevent system instability and terminal flooding, the kernel enforces technical bounds on logging configuration. These values control the **deduplication window**: a packet hitting a rule for the first time is logged, and subsequent identical packets are suppressed until the lifetime expires.

| Parameter | Default (SMB) | Enforced Range | Description |
|-----------|---------------|----------------|-------------|
| `LOGINFO_LIFETIME` | 30s | 5s – 600s | The TTL for a deduplication entry. |
| `MAX_LOGINFO_ENTRIES` | 256 | 64 – 65536 | The maximum number of distinct flows to track for deduplication. |

If a user attempts to set values outside these bounds via the Netlink interface, the kernel will automatically adjust them to the nearest limit and print a warning in `dmesg`.

## 4.6. Installation & Systemd Integration

### Building the Project
IPFire-Wall relies on two distinct compilation processes: one for the kernel module and one for the userspace application.

1.  **Kernel Module (`ipfi.ko`)**:
    Navigate to the `kernel/` directory and use the provided `Makefile`. You will need the Linux headers for your currently running kernel installed.
    ```bash
    cd kernel/
    make
    ```
    This produces the `ipfi.ko` module, which must be loaded by the `sysadmin` or automatically via the system service before starting the userspace application.

2.  **Userspace Application (`ipfire`)**:
    The userspace tools and configuration libraries are built using CMake from the `ipfi/` subdirectory.
    ```bash
    cd ipfi/
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr
    sudo cmake --build build --target install
    ```
    *Note: The `CMAKE_INSTALL_PREFIX` dictates where the binaries (`/bin/`), configuration files (`/etc/ipfire/`), and shared language assets (`/share/ipfire/`) will be installed. If omitted, it defaults to `/usr/local`.*

### Systemd Service Setup
When the userspace project is installed via `make install`, a Systemd unit file (`ipfire.service`) is automatically placed into `${CMAKE_INSTALL_PREFIX}/etc/systemd/system/`.

This service automates the lifecycle of both the kernel module and the userspace daemon:

- **Start (`systemctl start ipfire`)**:
  The service executes `/usr/bin/ipfire -rc -user`. This tells the userspace application to load all Root configuration rules (`-rc`) into the kernel immediately securely setting them at the highest priority. It then detaches into the background and simultaneously allows standard users (`-user`) to begin defining and managing their personal packet filtering rules.

- **Stop (`systemctl stop ipfire`)**:
  Systemd automatically sends a `SIGTERM` signal to all processes in the service's cgroup. The `ipfire` application intercepts this signal, frees its memory, cleanly unloads from the kernel socket, and prints a comforting exit message:
  *"The application has been closed due to a service stop (SIGTERM)."*
  Afterward, the service runs `modprobe -r ipfi` to safely remove the kernel module. If a user is currently running a foreground `ipfire` instance (outside Systemd), the module removal will fail gracefully, ensuring active sessions are not interrupted.

- **Reload (`systemctl reload ipfire`)**:
  Systemd sends a `SIGHUP` signal to the `ipfire` main process. The application catches the `SIGHUP` and prints:
  *"The application has been closed due to a service reload (SIGHUP)."*
  The service then removes the kernel module, clearing all state, and re-executes the startup sequence (`ipfire -rc -user`) to apply fresh configurations.
