# IPFire Packet Flow Walkthrough

This document provides comprehensive walkthroughs of packet flows through the IPFire kernel firewall module for three representative rules from `allowed.base`. Each walkthrough demonstrates different firewall concepts and provides detailed diagrams showing packet traversal through Netfilter hooks and the IPFire filtering engine.

---

## Rule Selection

We analyze three conceptually different rules that showcase the firewall's capabilities:

1. **HTTP Connection (Stateful)** - Basic stateful connection tracking
2. **FTP Control Connection (Passive FTP)** - Dynamic state creation for data channels
3. **SSH Bidirectional Access** - Both INPUT and OUTPUT paths with state tracking

---

## Rule 1: HTTP Connection (Stateful)

### Rule Definition
```
RULE
NAME=me -> www
DIRECTION=OUTPUT
MYSRCADDR
PROTOCOL=6
DSTPORT=80
KEEP_STATE=YES
```

### Scenario
A user on the firewall machine initiates an HTTP connection to a web server at `203.0.113.50:80`.

### Outgoing SYN Packet Flow

```mermaid
flowchart TD
    subgraph Userspace
        App([Application]) -->|sendto/write| Socket[Socket Layer]
    end

    subgraph Kernel_Network_Stack [Linux Kernel Network Stack]
        Socket --> TCP[TCP Stack: Create SYN]
        TCP --> Hook_LOCAL_OUT{NF_IP_LOCAL_OUT}
    end

    subgraph IPFire_Engine [IPFire Filtering Engine]
        Hook_LOCAL_OUT -- Packet --> Process[ipfire.c: process]
        Process --> Response[ipfi_response]
        
        subgraph Logic [Filtering Logic]
            Response --> CheckState{check_state}
            CheckState -- Miss --> Filter[ipfire_filter]
            Filter -- Match: 'me -> www' --> KeepState[keep_state]
        end
        
        KeepState --> NewEntry[Create state_table entry]
        NewEntry --> Hash[Add to state_hashtable]
    end

    subgraph State_Transitions [State Machine]
        NewEntry --> SYN_SENT[[State: SYN_SENT]]
        SYN_SENT --> Timer[Start Timeout Timer]
    end

    KeepState --> Verdict[Verdict: IPFI_ACCEPT]
    Verdict --> Accept[NF_ACCEPT]
    Accept --> Hook_POST_ROUTING{NF_IP_POST_ROUTING}
    Hook_POST_ROUTING --> Net((Network))

    %% Styling
    classDef hook fill:#f9f,stroke:#333,stroke-width:2px;
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef state fill:#dfd,stroke:#333,stroke-width:2px;
    classDef match fill:#9f9,stroke:#333,stroke-width:2px;

    class Hook_LOCAL_OUT,Hook_POST_ROUTING hook;
    class Process,Response,Logic,KeepState engine;
    class SYN_SENT state;
    class Verdict match;
```

#### Key Operations

1. **Hook Entry**: `NF_IP_LOCAL_OUT` invokes `ipfi_response()` with `flow.direction = IPFI_OUTPUT`
2. **State Check**: `check_state()` searches hash table - no match (new connection)
3. **Rule Matching**: `ipfire_filter()` iterates through permission rules
4. **Rule Match**: Matches `me -> www` (protocol=6, dport=80, MYSRCADDR, OUTPUT)
5. **State Creation**: `keep_state()` allocates new `state_table`:
   ```c
   state_table {
       saddr: 192.0.2.100        // Local firewall IP
       daddr: 203.0.113.50       // Web server IP
       sport: 54321              // Ephemeral port
       dport: 80                 // HTTP
       protocol: IPPROTO_TCP
       state: SYN_SENT
       direction: IPFI_OUTPUT
       rule_id: <hash of rule>
   }
   ```
6. **Hash Table**: Entry added to `state_hashtable` using `jhash_3words(saddr, daddr, ports)`
7. **Timer**: Setup timer expires in ~120 seconds (setup/shutdown timeout)
8. **Verdict**: Returns `NF_ACCEPT`

### Returning SYN-ACK Packet Flow

```mermaid
flowchart TD
    Net((Network)) --> Hook_PRE{NF_IP_PRE_ROUTING}
    
    subgraph IPFire_Pre [IPFire Pre-Processing]
        Hook_PRE --> PreProcess[ipfi_pre_process]
        PreProcess --> DNAT{Check DNAT}
        DNAT -- No Match --> Route[Routing Decision]
    end

    Route -- Local Delivery --> Hook_LOCAL_IN{NF_IP_LOCAL_IN}

    subgraph IPFire_Core [IPFire Core Engine]
        Hook_LOCAL_IN --> ProcessIn[ipfire.c: process]
        ProcessIn --> ResponseIn[ipfi_response]
        
        subgraph LogicIn [Stateful Lookup]
            ResponseIn --> CheckStateIn{check_state}
            CheckStateIn -- "Hit (Reverse)" --> Entry[Existing state_table]
        end
    end

    subgraph Machine [State Machine]
        Entry --> Transition[state_machine: SYN_SENT -> SYN_RECV]
        Transition --> UpdateTimer[Refresh Timer]
    end

    Entry --> VerdictIn[Verdict: IPFI_ACCEPT]
    VerdictIn --> AcceptIn[NF_ACCEPT]
    AcceptIn --> App([Application])

    %% Styling
    classDef hook fill:#f9f,stroke:#333,stroke-width:2px;
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef state fill:#dfd,stroke:#333,stroke-width:2px;
    classDef match fill:#9f9,stroke:#333,stroke-width:2px;

    class Hook_PRE,Hook_LOCAL_IN hook;
    class PreProcess,ResponseIn,LogicIn engine;
    class Transition,UpdateTimer state;
    class VerdictIn match;
```

#### Key Operations

1. **Reverse Match**: `check_state()` finds entry with **reverse** matching:
   ```c
   // Packet has: src=203.0.113.50:80, dst=192.0.2.100:54321
   // State table: saddr=192.0.2.100:54321, daddr=203.0.113.50:80
   reverse_state_match() -> returns 1
   ```
2. **State Machine**: `state_machine()` transitions `SYN_SENT + (SYN|ACK)` → `SYN_RECV`
3. **Timer Update**: `update_timer_of_state_entry()` extends timeout to established connection timeout (~3600 seconds)
4. **No Rule Check**: Since state matched, `ipfire_filter()` is **not called**
5. **Verdict**: Returns `NF_ACCEPT` based on state match

### Established Connection Data Flow

```mermaid
flowchart TD
    subgraph Traffic [Bidirectional Traffic]
        Pkt[Subsequent Packet] --> Lookup{check_state}
    end

    subgraph Fast_Path [Stateful Fast Path]
        Lookup -- "Match (Direct/Reverse)" --> State[State: ESTABLISHED]
        State --> Refresh[Update Timer]
        Refresh --> Accept[Verdict: IPFI_ACCEPT]
    end

    Accept --> Bypass[[Bypass Rule Evaluation]]
    Bypass --> NF_Accept[NF_ACCEPT]

    %% Styling
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef fast fill:#9f9,stroke:#333,stroke-width:2px;
    
    class Lookup engine;
    class State,Refresh,Accept,Bypass fast;
```

#### Performance Note
Once state is `ESTABLISHED`, all subsequent packets bypass rule evaluation entirely, providing high-performance stateful filtering via hash table lookup.

---

## Rule 2: FTP Control Connection (Passive FTP)

### Rule Definition
```
RULE
NAME=me -> ftp control
DIRECTION=OUTPUT
MYSRCADDR
PROTOCOL=6
DSTPORT=21
KEEP_STATE=YES
FTP_SUPPORT=YES
```

### Scenario
User initiates FTP connection to `203.0.113.100:21` and enters passive mode (PASV).

### Control Connection Establishment

The initial FTP control connection follows the same flow as HTTP (Rule 1), with state tracking for `<local>:ephemeral <-> <server>:21`.

### PASV 227 Response Flow

When the server sends a PASV 227 reply like:
```
227 Entering Passive Mode (203,0,113,100,195,210)
```

This encodes data channel endpoint: `203.0.113.100:50130` (195*256 + 210)

```mermaid
flowchart TD
    subgraph Control_Connection [Control Channel - state: FTP_LOOK_FOR]
        PacketIn[Packet with '227' code] --> CheckState{check_state}
        CheckState -- Reverse Hit --> StateTable[State table entry]
    end

    subgraph FTP_Helper [FTP Helper: helpers/ftp.c]
        StateTable --> Helper[ftp_support]
        Helper --> Parse[packet_contains_ftp_params]
        Parse --> Extract[Extract IP/Port from Payload]
    end

    subgraph Dynamic_State_Creation [State Management]
        Extract --> NewEntry[Create Dynamic state_table]
        NewEntry --> Flags[Set flag: FTP_DEFINED]
        Flags --> AddList[add_ftp_dynamic_rule]
    end

    AddList --> Accept[NF_ACCEPT]

    %% Styling
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef helper fill:#fba,stroke:#333,stroke-width:2px;
    classDef dynamic fill:#dfd,stroke:#333,stroke-width:2px;

    class CheckState,StateTable engine;
    class Helper,Parse,Extract helper;
    class NewEntry,Flags,AddList dynamic;
```

#### Key Operations

1. **FTP Flag Check**: Control connection state has `ftp = FTP_LOOK_FOR`
2. **Payload Inspection**: `ftp_support()` in `helpers/ftp.c` scans TCP payload
3. **227 Detection**: `data_start_with_227()` confirms "227" at start of data
4. **Parameter Extraction**: 
   ```c
   // Parses: (203,0,113,100,195,210)
   ftp_info {
       ftp_addr: 203.0.113.100 (in network order)
       ftp_port: 50130 (195*256 + 210, in network order)
       valid: 1
   }
   ```
5. **Dynamic State Creation**:
   ```c
   struct state_table *newt = kmalloc(...)
   newt->saddr = <local_ip>
   newt->sport = 0              // ANY source port
   newt->daddr = 203.0.113.100  // From FTP response
   newt->dport = 50130          // From FTP response
   newt->ftp = FTP_DEFINED      // Special FTP state
   newt->state = IPFI_NOSTATE
   ```
6. **Special Matching**: When matching FTP_DEFINED states, source port is **ignored** in first packet

### Data Connection Flow

```mermaid
flowchart TD
    DataPkt[Data Packet: SYN to 50130] --> Hook_OUT{NF_IP_LOCAL_OUT}
    
    subgraph State_Match [State Stateful Match]
        Hook_OUT --> Lookup{check_state}
        Lookup -- Match ignoring sport --> Match[FTP_DEFINED Entry]
    end

    subgraph State_Upgrade [State Evolution]
        Match --> Upgrade[Update entry with actual sport]
        Upgrade --> Established[Set flag: FTP_ESTABLISHED]
    end

    Established --> Machine[state_machine: NEW -> SYN_SENT]
    Machine --> Accept[NF_ACCEPT]

    %% Styling
    classDef hook fill:#f9f,stroke:#333,stroke-width:2px;
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef evolution fill:#dfd,stroke:#333,stroke-width:2px;

    class Hook_OUT hook;
    class Lookup,Match engine;
    class Upgrade,Established,Machine evolution;
```

#### FTP State Transitions
```
Control: ESTABLISHED (ftp=FTP_LOOK_FOR)
         ↓ (227 response detected)
Dynamic: Created (ftp=FTP_DEFINED, sport=0)
         ↓ (First outgoing packet)
Data:    ESTABLISHED (ftp=FTP_ESTABLISHED, sport=<actual>)
```

---

## Rule 3: SSH Bidirectional Access

### Rule Definitions
```
RULE
NAME=me -> secure shell
DIRECTION=OUTPUT
MYSRCADDR
PROTOCOL=6
DSTPORT=22
KEEP_STATE=YES

RULE
NAME=secure shell -> me
DIRECTION=INPUT
MYDSTADDR
PROTOCOL=6
DSTPORT=22
KEEP_STATE=YES
```

### Scenario A: Outgoing SSH Connection

This follows the same stateful flow as Rule 1 (HTTP), but to `dport=22`.

### Scenario B: Incoming SSH Connection

User connects FROM `203.0.113.200` TO the firewall's SSH server at `192.0.2.100:22`.

```mermaid
flowchart TD
    Client((External Client)) --> Hook_PRE{NF_IP_PRE_ROUTING}
    
    subgraph Core [IPFire Filtering Core]
        Hook_PRE --> Routing[Routing: Local]
        Routing --> Hook_IN{NF_IP_LOCAL_IN}
        Hook_IN --> Response[ipfi_response]
        
        subgraph Logic [Rule Check]
            Response --> CheckState{check_state}
            CheckState -- Miss --> Filter[ipfire_filter]
            Filter -- "Match: 'ssh -> me'" --> Match[Match Found]
        end
        
        Match --> KeepState[keep_state]
    end

    subgraph State [State Creation]
        KeepState --> NewEntry[New state_table entry]
         NewEntry --> SYN_RECV[[State: SYN_RECV]]
    end

    NewEntry --> Accept[NF_ACCEPT] --> SSHD([SSH Daemon])

    %% Styling
    classDef hook fill:#f9f,stroke:#333,stroke-width:2px;
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef state fill:#dfd,stroke:#333,stroke-width:2px;

    class Hook_PRE,Hook_IN hook;
    class Response,Logic,Filter engine;
    class NewEntry,SYN_RECV state;
```

### Return Traffic (SYN-ACK from SSH daemon)

```mermaid
flowchart TD
    SSHD([SSH Daemon]) --> Hook_OUT{NF_IP_LOCAL_OUT}
    
    subgraph Stateful_Engine [IPFire Stateful Engine]
        Hook_OUT --> Lookup{check_state}
        Lookup -- "Hit (Reverse)" --> Entry[Existing State]
    end

    subgraph Transitions [State Machine]
        Entry --> Machine[state_machine: SYN_RECV -> ESTABLISHED]
    end

    Machine --> Accept[NF_ACCEPT] --> Client((External Client))

    %% Styling
    classDef hook fill:#f9f,stroke:#333,stroke-width:2px;
    classDef engine fill:#bbf,stroke:#333,stroke-width:2px;
    classDef state fill:#dfd,stroke:#333,stroke-width:2px;

    class Hook_OUT hook;
    class Lookup,Entry engine;
    class Machine state;
```

### Bidirectional Flow Diagram

```mermaid
sequenceDiagram
    participant Client as External Client<br/>203.0.113.200
    participant FW_IN as Firewall<br/>INPUT Hook
    participant FW_OUT as Firewall<br/>OUTPUT Hook
    participant Daemon as SSH Daemon<br/>192.0.2.100:22
    
    Client->>FW_IN: SYN (dport=22)
    Note over FW_IN: Rule: "secure shell -> me"<br/>Creates state (direction=INPUT)
    FW_IN->>Daemon: SYN (ACCEPT)
    
    Daemon->>FW_OUT: SYN-ACK
    Note over FW_OUT: State: REVERSE match<br/>No rule check needed
    FW_OUT->>Client: SYN-ACK (ACCEPT)
    
    Client->>FW_IN: ACK + Data
    Note over FW_IN: State: Direct match<br/>(ESTABLISHED)
    FW_IN->>Daemon: Data packets
    
    Daemon->>FW_OUT: Data
    Note over FW_OUT: State: Reverse match<br/>(ESTABLISHED)
    FW_OUT->>Client: Data packets
```

---

## State Matching Logic

### Direct vs. Reverse Matching

The firewall uses sophisticated matching to handle bidirectional traffic:

#### Direct Match
```c
// State table: saddr=A, daddr=B, sport=X, dport=Y, direction=OUTPUT
// Packet:      src=A,   dst=B,   sport=X, dport=Y, hook=LOCAL_OUT
// Result: MATCH (same direction, same addresses/ports)
```

#### Reverse Match
```c
// State table: saddr=A, daddr=B, sport=X, dport=Y, direction=OUTPUT
// Packet:      src=B,   dst=A,   sport=Y, dport=X, hook=LOCAL_IN
// Result: MATCH (opposite direction, swapped addresses/ports)
```

### Hash Table Optimization

State lookups use bidirectional hash normalization:

```c
u32 get_state_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto)
{
    // Normalize: smaller address/port first
    if (saddr > daddr || (saddr == daddr && sport > dport)) {
        swap(saddr, daddr);
        swap(sport, dport);
    }
    return jhash_3words(saddr, daddr, (sport << 16) | dport, proto);
}
```

This ensures both directions of a connection hash to the same bucket.

---

## Timer Management

### State Timeouts

| State | Timeout | Description |
|-------|---------|-------------|
| SYN_SENT | 120s | Setup phase |
| SYN_RECV | 120s | Setup phase |
| ESTABLISHED | 3600s | Active connection |
| FIN_WAIT | 120s | Shutdown phase |
| TIME_WAIT | 120s | Connection closing |

### Timer Optimization

Timers are only updated if >1 second has passed since last update:

```c
void update_timer_of_state_entry(struct state_table *sttable)
{
    unsigned long now = jiffies;
    if (time_after(now, sttable->last_timer_update + HZ)) {
        mod_timer(&sttable->timer_statelist, 
                  jiffies + get_timeout_by_state(sttable->protocol, sttable->state) * HZ);
        sttable->last_timer_update = now;
    }
}
```

This reduces `mod_timer` overhead for high-throughput connections.

---

## Performance Characteristics

### Rule Evaluation Bypass

Once a state is established:
- **State lookup**: O(1) hash table lookup
- **Rule evaluation**: Skipped entirely
- **Throughput impact**: Minimal (only hash computation + state machine update)

### Comparison

| Packet Type | State Lookup | Rule Evaluation | Verdict Source |
|-------------|--------------|-----------------|----------------|
| New connection SYN | Miss | Full scan | Rule match |
| Return SYN-ACK | Hit (reverse) | Skipped | State |
| Established data | Hit (direct/reverse) | Skipped | State |
| Unrelated packet | Miss | Full scan | Default policy |

---

## Summary

These three rules demonstrate:

1. **Stateful HTTP**: Basic hash-based connection tracking eliminates rule re-evaluation
2. **FTP with Passive Mode**: Dynamic state creation allows data channels through firewall
3. **Bidirectional SSH**: Separate INPUT/OUTPUT rules with unified state tracking

The IPFire architecture achieves high performance through:
- Hash table-based state lookups
- Bidirectional connection normalization  
- Timer optimization for high-throughput connections
- Bypass of rule evaluation for established states
