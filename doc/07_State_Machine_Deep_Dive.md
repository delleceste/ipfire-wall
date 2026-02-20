# TCP/UDP State Machine: Deep Dive (Technical Master Edition)

This chapter provides an exhaustive analysis of the IPFire state machine, detailing how it tracks connection lifetimes, handles exceptions, and optimizes performance for high-throughput flows.

---

## 1. TCP State Lifecycle

The state machine implements a robust subset of RFC 793 to track connection health.

### 1.1. State Transition Table

The following table summarizes the legal transitions within the IPFire kernel.

| Current State | Event (Flags) | Next State | Logic Context |
|---------------|---------------|------------|---------------|
| `NOSTATE` | `SYN` (Out/In) | `SYN_SENT` | Initial Handshake Start |
| `SYN_SENT` | `SYN+ACK` (Rev) | `SYN_RECV` | Handshake Response |
| `SYN_RECV` | `ACK` (Dir) | `ESTABLISHED`| Connection Fully Open |
| `ESTABLISHED` | `FIN` (Out/In) | `FIN_WAIT` | Teardown Start |
| `FIN_WAIT` | `ACK` (Rev) | `CLOSE_WAIT`| Two-stage Termination |
| `ANY` | `RST` | `CLOSED` | Immediate Teardown |

### 1.2. The Three-Way Handshake Core Logic

The implementation in `ipfi_state_machine.c` ensures strict flag checking during the setup phase:

```c
// handshake logic segment
if (syn && !ack && !rst && !fin) {
    if (current_state == NOSTATE) return SYN_SENT;
}

if (syn && ack && !rst && !fin && reverse) {
    if (current_state == SYN_SENT) return SYN_RECV;
}

if (!syn && ack && !rst && !fin && !reverse) {
    if (current_state == SYN_RECV) return ESTABLISHED;
}
```

---

## 2. Timer Aggregation Logic

To avoid the performance penalty of frequent timer renewals (`mod_timer` syscall overhead), IPFire implements a "1-second throttle".

### 2.1. Why Aggregation?
In a high-speed Gbit link, a single connection might send thousands of packets per second. Updating the kernel timer for every packet would consume excessive CPU cycles.

### 2.2. The Implementation
The engine only updates the timer if at least 1 second (measured in `HZ` / Jiffies) has elapsed since the last update.

```c
void update_timer_of_state_entry(struct state_table *sttable) {
    unsigned long now = jiffies;
    // HZ represents 1 second in kernel-time
    if (time_after(now, sttable->last_timer_update + HZ)) {
        mod_timer(&sttable->timer_statelist, 
                  jiffies + get_timeout_by_state(sttable->protocol, sttable->state) * HZ);
        sttable->last_timer_update = now;
    }
}
```

---

## 3. GUESS States & Normalization

GUESS states are a unique feature of IPFire that allows it to "adopt" existing connections that were established before the module was loaded.

### 3.1. Mid-Flow Connection Detection
If a packet arrives that is NOT a SYN but has no matching state, the machine "guesses" where it belongs.

```c
// GUESS_ESTABLISHED detection
if (!rst && !fin && !syn && ack && (current_state == NOSTATE)) {
    return GUESS_ESTABLISHED;
}
```

### 3.2. Normalization on Storage
The engine returns a GUESS state for accounting, but **normalizes** it to a standard state before storing it in the hash table. This ensures future packets follow standard RFC transitions.

```c
// Normalization logic in set_state()
if (found_state == GUESS_ESTABLISHED) {
    entry->state.state = ESTABLISHED;
} else if (found_state == GUESS_SYN_RECV) {
    entry->state.state = SYN_RECV;
}
```

---

## 4. UDP "Pseudo-States"

Since UDP is stateless, the machine uses timeout-based persistence to simulate connection tracking.

- **`UDP_NEW`**: Created on the first packet.
- **`UDP_ESTAB`**: Promoted on the first *return* packet (where `reverse == 1`).
- **Timeout**: Typically 30-60 seconds of inactivity.

---

## 5. Security & Established Flow Bypass

One of the most important design decisions is that **Established flows bypass permission rules entirely.**

### Why?
1.  **Consistency**: Once a connection is allowed by a rule, it should remain allowed until it closes. If a firewall rule changes mid-connection, the active stream isn't "cut" unless explicitly flushed.
2.  **Performance**: Rule lists can be long (O(N)). Hash table lookups are O(1). By skipping the list for millions of data packets, we save massive amounts of CPU time.
