# Hash Functions in ipfire-wall: Design and Rationale

This chapter documents the hash functions used by the three kernel-side
lookup tables — **State**, **SNAT/DNAT (NAT)**, and **Log deduplication** —
explains how each one maps a packet to a bucket, and motivates the deliberate
difference between the 5-tuple approach used by state/NAT tables and the
3-tuple approach used by the log table.

---

## Background: kernel hash tables

ipfire-wall uses the kernel's `linux/hashtable.h` API (available since
Linux 3.7 and documented in
[`Documentation/core-api/kernel-api.rst`][kernel-api]).

The API provides fixed-size, power-of-two hash tables with open chaining
via `struct hlist_head` / `struct hlist_node`.  The number of buckets is
`1 << BITS`, chosen at compile time.  Bucket selection is:

```c
bucket = hash_value & HASH_MASK;   /* HASH_MASK = (1 << BITS) - 1 */
```

Iteration over a specific bucket uses `hash_for_each_possible_rcu(ht, obj,
member, key)`: it hands `key` to the same masking step and walks only the
matching chain, making the common case O(chain-length) rather than O(N).

The hash values themselves are computed with Bob Jenkins' `jhash` family
([`include/linux/jhash.h`][jhash-h]):

| function | inputs |
|---|---|
| `jhash_2words(a, b, initval)` | two 32-bit words |
| `jhash_3words(a, b, c, initval)` | three 32-bit words |

Both mix the inputs with a series of XOR/shift/add rounds, producing a
well-distributed 32-bit output with no collisions observed for structured
network-address inputs under normal traffic patterns.

[kernel-api]: https://www.kernel.org/doc/html/latest/core-api/kernel-api.html
[jhash-h]: https://elixir.bootlin.com/linux/latest/source/include/linux/jhash.h

---

## State table — 5-tuple, symmetric key

**File:** `filter/state/state_table.c`  
**Macro:** `STATE_HASH_BITS` (default 10 → 1024 buckets)

### Hash function

```c
/* from state_table.c — lookup direction */
key = jhash_2words(
    ((u32)saddr << 16) | daddr,   /* pack both IPs */
    ((u32)sport  << 16) | dport,  /* pack both ports */
    protocol                       /* initval doubles as proto seed */
);
```

> **Symmetry.** The exact key formula (and whether IP/port pairs are
> sorted before hashing) can vary; what matters is that both the
> *insertion* path and the *lookup* path compute the key identically
> from the packet's 5-tuple.

### Why 5-tuple?

A state entry represents **one specific bidirectional connection**.  Two
flows between the same hosts on different ports are independent connections
with independent timers, states, and verdict rules.  A 5-tuple key gives
each flow its own, nearly-unique bucket address, keeping per-bucket chains
to O(1) even at tens of thousands of concurrent connections.

Using fewer fields (e.g. 3-tuple) would force unrelated connections into
the same bucket, lengthening chains and degrading lookup performance
proportionally — exactly the problem hash tables exist to avoid.

---

## SNAT and DNAT tables — 5-tuple, relation-aware key

**Files:** `nat/nat_table.c`, `nat/dnat/dnat.c`, `nat/snat/snat.c`  
**Macro:** `NAT_HASH_BITS` (default 8 → 256 buckets)

#### 3. Table Sizing: Why `1 << BITS`?

We deliberately size all hash tables as a **Power of Two** using the left-shift operator (e.g., `1 << 10` = 1024).

**The Intent (Performance):**
*   **Modulo (`%`) is Slow:** Finding a bucket index using division (`key % size`) is computationally expensive.
*   **Masking (`&`) is Fast:** If the size is a power of 2, we can use a bitwise AND mask (`key & (size - 1)`) to find the bucket. This is an incredibly fast CPU operation.

By using `1 << BITS`, we guarantee the size is compatible with this fast masking optimization.

### Hash functions

```c
/* from nat_table.c */

/* SNAT: keyed on (new source, original dest) */
u32 get_snat_hash(__u32 new_saddr, __u16 new_sport,
                  __u32 old_daddr, __u16 old_dport, __u8 proto)
{
    /* Sort the two address/port pairs so that
     * (A→B) and (B→A) land in the same bucket. */
    __u32 a1 = new_saddr, a2 = old_daddr;
    __u16 p1 = new_sport, p2 = old_dport;
    if (a1 > a2 || (a1 == a2 && p1 > p2)) {
        swap(a1, a2);
        swap(p1, p2);
    }
    return jhash_3words(a1, a2,
                        ((u32)p1 << 16) | p2, proto);
}

/* DNAT: keyed on (original source, new dest) — same structure */
u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport,
                  __u32 new_daddr, __u16 new_dport, __u8 proto);
```

### Why 5-tuple and why sorted?

NAT entries must be found both on the *forward* path (look up translation
for outgoing packets) and on the *reverse* path (de-NAT reply packets).
The forward packet carries `(saddr, sport, daddr, dport)` in one order;
the reply carries the same four addresses in the opposite roles.

Sorting the two endpoint pairs before hashing makes both directions
produce the **same bucket key**, so a single `hash_for_each_possible_rcu`
call on the sorted 5-tuple finds the entry regardless of which direction
triggered the lookup.

The full `(addr, addr, port, port, proto)` 5-tuple still applies here for
the same reason as in the state table: two NAT sessions between the same
hosts on different ports are distinct entries.

---

## Log deduplication table — 3-tuple key

**File:** `logging/log.c`  
**Macro:** `LOG_HASH_BITS` (default 7 → 128 buckets)

### Hash function

```c
/* from log.c */
static u32 get_log_hash(__be32 saddr, __be32 daddr, __u8 proto)
{
    return jhash_3words((__u32)saddr, (__u32)daddr, proto, 0);
}
```

Only **source address, destination address, and protocol** are hashed.
Ports are omitted.

### Why not 5-tuple?

The log table has a fundamentally different role from the state/NAT tables.

**State/NAT lookup contract:** given a packet's 5-tuple, return *one
specific entry* that was previously inserted for exactly that flow.

**Log deduplication contract** (`packet_not_seen`): given a packet, answer
"have I recently logged something similar?" The final equality test is
performed by `compare_loginfo_packets()`, which does a full struct
comparison covering IPs, ports, TCP flags, direction, rule ID, and
connection state.  The hash key is only a **pre-filter** — it routes the
lookup to the correct bucket; the per-entry comparison does the real work.

Given this two-phase design, a 3-tuple key is preferable for two reasons:

#### 1. Protocol generality

ICMP, IGMP, GRE, and PIM carry no port numbers.  A port-inclusive key
would require per-protocol branching:

```c
/* What a 5-tuple log hash would look like — note the special cases */
if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
    key = jhash_3words(saddr, daddr, ((u32)sport << 16) | dport, proto);
else
    key = jhash_3words(saddr, daddr, 0, proto);  /* special case */
```

The 3-tuple eliminates this branching: `jhash_3words(saddr, daddr, proto,
0)` works identically for all protocols without any conditional.

The kernel's own connection-tracking helper for ICMP (`nf_conntrack_icmp`)
uses a similar 3-tuple (src, dst, type/code) precisely because ICMP
direction reversals map IDs rather than ports — the same portless design
rationale applies here.

#### 2. Log semantic: entries represent traffic classes, not individual flows

A state entry is a *conversation*: two hosts, two ports, one protocol,
tracking flags, timers, and verdict.  Two TCP connections from client
`192.168.1.5` to server `10.0.0.1:80` on ports 54321 and 54322 are
completely independent state entries.

A log entry is a *firewall observation*: "traffic of this type between
these hosts was seen and logged."  Two TCP connections from the same client
to the same server, matched by the same firewall rule, represent the same
observable event from a log-deduplication standpoint.  Placing them in the
same bucket is semantically correct; if `compare_loginfo_packets()` later
decides they differ (different port, different flag state), it will return
false and both events will be logged individually.

Grouping by (saddr, daddr, proto) rather than by full 5-tuple thus
**reduces unnecessary log volume** for bursty short-lived connections
(think: many parallel HTTP/2 streams from the same client), which is the
primary goal of the deduplication mechanism.

#### 3. Table size

With `LOG_HASH_BITS=7` (128 buckets) and `max_loginfo_entries` set to a
few hundred by default, buckets hold at most a handful of entries.  The
marginal improvement of a 5-tuple key over a 3-tuple key is negligible at
this scale: the chain-scan in `compare_loginfo_packets()` is bounded and
cache-hot.

---

## Comparison summary

| | State | SNAT / DNAT | Log dedup |
|---|---|---|---|
| **Hash key** | 5-tuple | 5-tuple (sorted) | 3-tuple |
| **Fields** | saddr, daddr, sport, dport, proto | new/old addr pairs + proto | saddr, daddr, proto |
| **Symmetry** | no | yes (sorted swap) | n/a |
| **Hash bits** | 10 (1024 bkts) | 8 (256 bkts) | 7 (128 bkts) |
| **Lookup role** | find exact entry | find exact entry | pre-filter only |
| **Final eq. test** | `forward_state_match()` | `forward_nat_match()` | `compare_loginfo_packets()` |
| **Portless protos** | special-cased (ICMP) | special-cased (ICMP) | uniform (no ports) |

---

## Further reading

- [`include/linux/hashtable.h`][ht-h] — `DEFINE_HASHTABLE`, `hash_for_each_possible_rcu`, `hlist_add_head_rcu`
- [`include/linux/jhash.h`][jhash-h] — `jhash_3words`, `jhash_2words`
- [Kernel documentation: RCU concepts][rcu-doc] — why `_rcu` variants of list/hash macros are needed in the datapath
- [Bob Jenkins, "A hash function for hash table lookup"][jenkins] — theoretical background for `jhash`

[ht-h]: https://elixir.bootlin.com/linux/latest/source/include/linux/hashtable.h
[rcu-doc]: https://www.kernel.org/doc/html/latest/RCU/whatisRCU.html
[jenkins]: http://burtleburtle.net/bob/hash/doobs.html
