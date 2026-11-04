
# Network Traffic Analysis — Complete Study Guide

> **How this guide works:** This file applies the *Learning How to Learn* techniques from the PDF directly to the HTB Academy Network Traffic Analysis module. You'll find **chunks** (small, digestible pieces), **visual metaphors** to anchor memory, **active-recall questions**, **spaced-repetition schedules**, **interleaved practice problems**, and **worked solutions**. Do not just read — *recall, test, and space* your practice. That is the whole point.

---

## Table of Contents

1. [How to Use This Guide (Learning How to Learn Applied)](Quick%2520clean%2520reference.md##1-how-to-use-this-guide)
2. [Chunk 0 — The Big Picture: What Is NTA?](Quick%2520clean%2520reference.md##2-chunk-0--the-big-picture)
3. [Chunk 1 — Networking Primer: Layers 1–4](Quick%2520clean%2520reference.md##3-chunk-1--networking-primer-layers-14)
4. [Chunk 2 — Networking Primer: Layers 5–7](Quick%2520clean%2520reference.md##4-chunk-2--networking-primer-layers-57)
5. [Chunk 3 — The Analysis Process (Descriptive → Prescriptive)](Quick%2520clean%2520reference.md##5-chunk-3--the-analysis-process)
6. [Chunk 4 — Analysis in Practice (Workflow + Approach)](Quick%2520clean%2520reference.md##6-chunk-4--analysis-in-practice)
7. [Chunk 5 — Tcpdump Fundamentals](Quick%2520clean%2520reference.md##7-chunk-5--tcpdump-fundamentals)
8. [Chunk 6 — Tcpdump Packet Filtering (BPF Syntax)](Quick%2520clean%2520reference.md##8-chunk-6--tcpdump-packet-filtering)
9. [Chunk 7 — Wireshark Basics](Quick%2520clean%2520reference.md##9-chunk-7--wireshark-basics)
10. [Chunk 8 — Wireshark Advanced Usage](Quick%2520clean%2520reference.md##10-chunk-8--wireshark-advanced-usage)
11. [Chunk 9 — RDP Decryption & Labs](Quick%2520clean%2520reference.md##11-chunk-9--rdp-decryption--labs)
12. [Master Cheat Sheet](Quick%2520clean%2520reference.md##12-master-cheat-sheet)
13. [Spaced-Repetition Schedule](Quick%2520clean%2520reference.md##13-spaced-repetition-schedule)
14. [Self-Test Answer Keys](Quick%2520clean%2520reference.md##14-self-test-answer-keys)

---

## 1. How to Use This Guide

### The Learning How to Learn Toolkit (Applied Here)

From the *Learning How to Learn* course, here are the principles you must use:

| Principle | What It Means | How to Apply in This Guide |
|---|---|---|
| **Focused mode** | Concentrated attention on familiar material | Read each chunk carefully, one at a time |
| **Diffuse mode** | Relaxed, big-picture thinking | After each chunk, take a walk/shower/nap and let it settle |
| **Chunking** | Bind bits of info through meaning | Each section below is one *chunk* — master it before moving on |
| **Recall / Active retrieval** | Look away and recall from memory | After each chunk, close the file and write what you remember |
| **Spaced repetition** | Repeat over days, not one cram session | Use the schedule in §13 |
| **Interleaving** | Mix different problem types | The practice problems mix topics deliberately |
| **Illusions of competence** | Rereading ≠ learning | Do the self-tests; don't just highlight |
| **Hard start, jump to easy** | Start hard, then switch | Try hard problems first, then easy, then return |
| **Process over product** | Focus on time spent, not finishing | Use Pomodoro: 25 min focused, 5 min break |
| **Sleep & exercise** | Consolidates memory | Study → sleep → review. Walk between chunks |
| **Visual metaphors** | Anchor abstract ideas | Each chunk has a **metaphor** box — build the image in your mind |
| **Testing effect** | Testing teaches more than rereading | Mini-tests after every chunk + final exam |
| **Memory palace** | Place images in familiar locations | Build a mental "network operations center" (see §2) |

### Your Pomodoro Plan

- **Session 1 (25 min):** Chunks 0–1
- **Break (5 min):** Walk, no phone
- **Session 2 (25 min):** Chunks 2–3
- **Break (5 min):** Stretch
- **Session 3 (25 min):** Chunks 4–5
- **Break (5 min):** Snack
- **Session 4 (25 min):** Chunks 6–7
- **Break (5 min):** Walk
- **Session 5 (25 min):** Chunks 8–9
- **Break (5 min):** Rest
- **Session 6 (25 min):** Master Cheat Sheet + Self-Test
- **Sleep** — this is when consolidation happens. Do not skip.

> **Barbara Oakley says:** "Taking a test without getting enough sleep means you're operating with a brain that's got little metabolic toxins floating around in it." Sleep is part of the study session, not a luxury.

---

## 2. Chunk 0 — The Big Picture

> **Metaphor (Diffuse mode):** Imagine you are a security guard in a **Network Operations Center (NOC)**. You have a giant wall of monitors showing every conversation in your building. Your job is to spot the *one* conversation that doesn't belong — the stranger in the crowd. **Network Traffic Analysis (NTA)** is the art of watching that wall, filtering out the noise, and spotting the stranger before they steal the crown jewels.

### What Is NTA?

`NTA` = examining network traffic to:
1. Characterize common ports & protocols
2. Establish a baseline for your environment
3. Monitor and respond to threats
4. Ensure insight into your organization's network

### Why It Matters

Attackers update tactics constantly, use legitimate credentials, and use tools companies allow. NTA helps defenders spot anomalies *early*.

### Everyday Use Cases (memorize these 5)

| Use Case | What It Means |
|---|---|
| **Collecting** | Real-time traffic analysis for upcoming threats |
| **Setting** | Baseline for day-to-day communications |
| **Identifying** | Non-standard ports, suspicious hosts, protocol issues (HTTP errors, TCP problems) |
| **Detecting** | Malware on the wire (ransomware, exploits, non-standard interactions) |
| **Investigating** | Past incidents and threat hunting |

### The NTA Workflow (memorize the 4-step loop + 1)

> **Visual:** Picture a **washing machine cycle**: Ingest → Filter → Analyze → Detect → (Fix & Monitor).

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 1. INGEST   │ ──▶ │ 2. REDUCE   │ ──▶ │ 3. ANALYZE  │ ──▶ │ 4. DETECT   │
│   TRAFFIC   │     │  NOISE      │     │  & EXPLORE  │     │  & ALERT    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                  │
                                                                  ▼
                                                          ┌─────────────┐
                                                          │ 5. FIX &    │
                                                          │  MONITOR    │
                                                          └─────────────┘
```

1. **Ingest** — Begin capturing traffic (use capture filters if you know what you're looking for)
2. **Reduce Noise** — Filter out broadcast, multicast, baseline traffic
3. **Analyze & Explore** — Look at specific hosts, protocols, TCP flags
4. **Detect & Alert** — Errors? Malicious? Use IDS/IPS, heuristics, signatures
5. **Fix & Monitor** (outside the loop) — Fix the issue and continue monitoring

### The NTA Mindset (from the module)

> *"To spot malicious traffic, we need to use our knowledge of typical network traffic within our enclave."*

- If you see many `SYN` packets on rarely-used ports → likely a **portscan**
- Know the baseline → outliers become obvious

### Required Skills (Self-Check)

Rate yourself 1–5 on each. Anything below 3 → review that chunk.

| Skill | Confidence (1–5) |
|---|---|
| TCP/IP Stack & OSI Model | |
| Basic Network Concepts (switching, routing) | |
| Common Ports & Protocols | |
| IP Packets & Sublayers | |
| Protocol Transport Encapsulation | |

### Common Traffic Analysis Tools (memorize the big three + extras)

| Tool | Description | Best For |
|---|---|---|
| **tcpdump** | CLI sniffer using LibPcap | Fast CLI captures, remote SSH |
| **TShark** | CLI variant of Wireshark | CLI + rich dissectors |
| **Wireshark** | GUI analyzer | Deep inspection, visual analysis |
| **NGrep** | Pattern-matching like `grep` for packets | HTTP/FTP debugging |
| **tcpick** | TCP stream reassembly | Rebuilding streams |
| **Network Taps** | Hardware copies of traffic | In-line/out-of-band capture |
| **SPAN Ports** | Switch/router port mirroring | Copying frames to a collector |
| **Elastic Stack** | Ingest + visualize data | Search & analysis at scale |
| **SIEMs (Splunk)** | Central analysis point | Alerting, forensics, day-to-day |

### BPF Syntax

`Berkeley Packet Filter (BPF)` = the shared filtering syntax across tcpdump, TShark, Wireshark capture filters.

- Enables a raw interface to read/write from the **Data-Link layer**
- Provides **filtering and decoding abilities**
- We use it through the module (tcpdump + Wireshark capture filters)

### Performing NTA — Passive vs Active

| Aspect | Passive | Active |
|---|---|---|
| Approach | Copy data you can see | In-line, hands-on |
| Permission | ☑ Required | ☑ Required |
| Mirrored Port | ☑ Required | ☐ |
| Capture Tool | ☑ | ☑ |
| In-line Placement | ☐ | ☑ |
| Network Tap / Multi-NIC | ☐ | ☑ |
| Storage & Processing | ☑ | ☑ (much more!) |

> **Metaphor:** Passive = filling a cup from a water fountain (steady, manageable). Active = filling a teacup from a fire hose (much more pressure, needs more resources).

---

### ⏸️ RECALL BREAK — Chunk 0

Close this file. Write down:
1. The 5 use cases of NTA
2. The 5-step workflow
3. The difference between passive and active capture
4. What BPF is and why we care

Then check your answers against the section above. **Do not reread first — recall first.**

---

## 3. Chunk 1 — Networking Primer: Layers 1–4

> **Metaphor (Focused):** Networking models are like **Russian nesting dolls**. Each layer wraps the one above it in its own "bubble" (encapsulation), and when the data arrives, the receiver unwraps them in reverse order. Wireshark shows you the dolls already unwrapped — bottom-up.

### OSI vs TCP/IP Models

| Trait | OSI | TCP-IP |
|---|---|---|
| Layers | 7 | 4 |
| Flexibility | Strict | Loose |
| Dependency | Protocol-independent & generic | Based on common protocols |

**Mapping:**
- OSI 5, 6, 7 → TCP/IP Application (layer 4)
- OSI 3 → TCP/IP Transport / Internet (layer 3 / layer 2)
- OSI 1, 2 → TCP/IP Link (layer 1)

> **Memory aid:** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing (OSI top→bottom: Application, Presentation, Session, Transport, Network, Data-Link, Physical)

### PDU (Protocol Data Unit) Encapsulation

```
[Application Data]
   ↓
[Segment/Datagram]  ← Transport layer (TCP/UDP header)
   ↓
[Packet]            ← Network layer (IP header)
   ↓
[Frame]             ← Data-Link layer (Ethernet header + trailer)
   ↓
[Bit]               ← Physical layer
```

> **Wireshark shows it in reverse** — because it un-encapsulates. Top of the detail pane = lowest layer.

### Addressing Mechanisms

#### MAC Address
- 48-bit, **six octets**, hexadecimal
- Used at **Layer 2** (Data-Link / Link)
- Host-to-host within a **broadcast domain**
- If traffic must cross a Layer 3 interface → sent to router's MAC, router strips L2, re-encapsulates with next hop's MAC

> **Example:** `00:0c:29:97:52:65` (the red arrow in the module's image)

#### IPv4
- 32-bit, **four octets**, decimal
- Layer 3 (Network) / Layer 2 (Internet)
- Each octet: `0`–`255`
- Example: `192.168.86.243`

#### IPv6
- 128-bit, **16 octets**, hexadecimal
- Example: shortened form like `2001:db8::1`
- Benefits: huge address space, multicast support, global addressing per device, IPSec built in, simplified headers

**IPv6 Address Types:**

| Type | Description |
|---|---|
| **Unicast** | Single interface (one-to-one) |
| **Anycast** | Multiple interfaces, one receives (load balancing) |
| **Multicast** | Multiple interfaces, all receive (one-to-many) |
| **Broadcast** | Does not exist; realized with multicast |

> **Adoption:** Only ~40% globally at time of writing.

### TCP vs UDP (Transport Mechanisms)

| Characteristic | TCP | UDP |
|---|---|---|
| Transmission | Connection-oriented | Connectionless ("fire and forget") |
| Connection Establishment | 3-way handshake | No check if destination is listening |
| Data Delivery | Stream-based | Packet-by-packet |
| Receipt of Data | Sequence + ACK numbers | Doesn't care |
| Speed | Slower, more overhead | Fast but unreliable |

> **Metaphor:** TCP = **phone call** (you confirm the other person is there, you acknowledge what they say, you say goodbye). UDP = **postcard** (you fire it off, hope it arrives, no confirmation).

**When to use:**
- TCP → SSH, file transfers, `sudo passwd` (completeness > speed)
- UDP → Streaming video, DNS (speed > completeness; drops are okay)

### TCP Three-Way Handshake

> **Visual:** Think of two people agreeing to dance:
> 1. You: "Wanna dance?" (SYN)
> 2. Partner: "Sure, let's dance!" (SYN-ACK)
> 3. You: "Great, let's go!" (ACK)

**Steps:**
1. **Client** sends packet with **SYN** flag set (synchronization) — negotiates sequence numbers, window size, MSS, selective ACKs
2. **Server** responds with **SYN + ACK** (acknowledges client's SYN, sends its own SYN)
3. **Client** responds with **ACK** — connection established

> **Packet pattern to memorize:** `SYN` → `SYN, ACK` → `ACK`

**What you see in a capture:**
- Line 1: `Flags [S]` — client random high port → server well-known port (e.g., 57678 → 80)
- Line 2: `Flags [S.]` — server → client (SYN-ACK)
- Line 3: `Flags [.]` — client → server (ACK)

### TCP Session Teardown

> **Visual:** Ending a phone call politely:
> 1. You: "Okay, I'm done talking" (FIN, ACK)
> 2. Them: "Got it, I'm done too" (FIN, ACK)
> 3. You: "Bye!" (ACK)

**Packet pattern to memorize:**
1. `FIN, ACK`
2. `FIN, ACK`
3. `ACK`

> **FIN flag** = "data transfer finished, requesting termination."

---

### ⏸️ RECALL BREAK — Chunk 1

Close the file. Answer:
1. Which OSI layers map to which TCP/IP layers?
2. What is a MAC address (bits, format, layer)?
3. What is an IPv4 address (bits, format, layer)?
4. List the 3 steps of the TCP handshake and the flags used.
5. List the 3-step teardown pattern.
6. TCP vs UDP: which is connection-oriented?

---

## 4. Chunk 2 — Networking Primer: Layers 5–7

> **Metaphor (Diffuse):** Layers 5–7 are where **humans** live. The lower layers are the postal system; the upper layers are the letters people actually write. HTTP is a postcard, HTTPS is a sealed envelope, FTP is a moving truck, SMB is a shared filing cabinet.

### HTTP (Hypertext Transfer Protocol)

- **Stateless** Application Layer protocol, in use since 1990
- Transfers data in **clear text** between client and server over **TCP**
- **Ports 80 or 8000** (normally); can use others, rarely UDP

**HTTP Methods:**

| Method | Required? | Description |
|---|---|---|
| **HEAD** | required | Like GET but no message body; useful for server info |
| **GET** | required | Most common; requests content from server |
| **POST** | optional | Submits info to server (forms, forum posts) |
| **PUT** | optional | Places data at URI; creates or updates object |
| **DELETE** | optional | Removes object at URI |
| **TRACE** | optional | Echoes the request back (diagnosis) |
| **OPTIONS** | optional | Lists supported methods |
| **CONNECT** | optional | Tunneling over HTTP (proxies, SSL tunnels) |

> **Memory aid:** GET and HEAD are **required** by the standard. Everything else is optional.

> **PUT vs POST:** PUT = create/update the *thing* at the URI. POST = create *child entities* under the URI. (Think: PUT creates a file; POST writes comments on the file's page.)

### HTTPS (HTTP Secure)

- HTTP + **TLS/SSL** encryption
- **Ports 443 and 8443** (instead of 80)
- Encrypts the entire conversation (not just data)
- Protects against MITM, reconnaissance, hijacking

**TLS Handshake (summary):**
1. Exchange hello messages → agree on connection parameters
2. Exchange cryptographic parameters → establish premaster secret
3. Exchange x.509 certificates → authentication
4. Generate master secret from premaster secret + random values
5. Issue negotiated security parameters to record layer
6. Verify peer calculated same parameters, no tampering

> **What you see in a capture:** TCP handshake → `TLS ClientHello` → `TLS ServerHello, Change Cipher Spec, Application Data...` → `Application Data` (encrypted) → TCP ACKs continue on port 443.

> **Metaphor:** TLS is a **sealed diplomatic pouch**. The courier (TCP) still delivers it, but nobody can read the contents except the intended recipient.

### FTP (File Transfer Protocol)

- Application Layer, transfers files between hosts
- **Insecure** by default (most moved to SFTP)
- Browsers phased out FTP support ~2020

**Unique feature:** Uses **two ports**:
- **Port 20** → data transfer
- **Port 21** → control commands

**Modes:**
- **Active** (default): server listens for `PORT` command from client, stating which port to use for data
- **Passive**: for clients behind firewalls/NAT; client sends `PASV`, server responds with IP + port for data channel

**Common FTP Commands (port 21):**

| Command | Description |
|---|---|
| **USER** | Specifies user to log in as |
| **PASS** | Sends password |
| **PORT** | (Active) changes data port |
| **PASV** | Switches to passive mode |
| **LIST** | Lists files in current directory |
| **CWD** | Changes working directory |
| **PWD** | Prints working directory |
| **SIZE** | Returns file size |
| **RETR** | Retrieves file from server |
| **QUIT** | Ends session |

> **Metaphor:** FTP is a **warehouse with two doors** — one door for talking to the clerk (port 21), one door for loading trucks (port 20).

### SMB (Server Message Block)

- Most widely seen in **Windows enterprise environments**
- **Connection-oriented**, requires **user authentication**
- Shares resources: printers, drives, authentication servers, etc.

**Transport evolution:**
- Old: NetBIOS over UDP 137/138
- Modern: **Direct TCP port 445**, NetBIOS over TCP 139, even QUIC

> **What you see in a capture:** TCP 3-way handshake each session → port **445** → SMB protocol negotiation, logon, errors.

**SMB Security Signal:**
- One or two auth failures = common
- **Large cluster of repeated auth failures** = suspicious (credential theft, lateral movement)
- **Host-to-host SMB** (two user PCs) = suspicious
- **Hosts accessing file shares on other hosts** = unusual; note who/where/what

---

### ⏸️ RECALL BREAK — Chunk 2

Close the file. Answer:
1. What port(s) does HTTP use? HTTPS?
2. Which HTTP methods are **required** by the standard?
3. What is the difference between PUT and POST?
4. What two ports does FTP use and what is each for?
5. What is the difference between FTP active and passive mode?
6. What port does modern SMB use?
7. What is a suspicious SMB pattern to look for?

---

## 5. Chunk 3 — The Analysis Process

> **Metaphor (Focused):** The analysis process is like **being a detective at a train station**. First you describe what you see (descriptive), then you figure out *why* the suspicious person is there (diagnostic), then you predict what they'll do next (predictive), then you decide what to do about it (prescriptive).

### What Is Traffic Analysis?

> *"A detailed examination of an event or process, determining its origin and impact, which can be used to trigger specific precautions and/or actions to support or prevent future occurrences."*

With network traffic: break data into understandable chunks, examine for deviations from regular traffic, look for malicious traffic (unauthorized remote comms like RDP/SSH/Telnet), or unique instances preceding network issues.

### Why NTA Matters

- **Visibility** is the most beneficial thing it provides
- Capturing over different periods → **baseline**
- Baseline makes **changes** easier to see
- Works with IDS/IPS, firewalls, host/network logs → richer context (Splunk, ELK)
- Also useful for **daily operations** (troubleshooting connectivity, protocol health)

> **Important:** "Using automated tools to aid us is perfectly fine. Just do not rely on them solely. ... The human eye is still our best resource for finding the bad."

### Active vs Passive Capture Dependencies

| Dependency | Passive | Active | Description |
|---|---|---|---|
| **Permission** | ☑ | ☑ | Written permission required (legal/ethical) |
| **Mirrored Port** | ☑ | ☐ | Switch/router port configured to copy data |
| **Capture Tool** | ☑ | ☑ | tcpdump, Wireshark, etc. |
| **In-line Placement** | ☐ | ☑ | Tap in-line requires topology change |
| **Network Tap / Multi-NIC** | ☐ | ☑ | Two NICs or a tap device |
| **Storage & Processing** | ☑ | ☑ (more) | Active on L3 link = much more traffic |

> **Metaphor:** Passive = pouring water from a fountain into a cup. Active = filling a teacup from a fire hose.

### The Analysis Types (memorize the 4)

#### 1. Descriptive Analysis
> *"Describes a data set based on individual characteristics. Detects possible errors in data collection and/or outliers."*

**Questions:**
1. What is the issue? (Suspected breach? Networking issue?)
2. Define scope and goal (what are we looking for? which time period?)
3. Define targets (net / host(s) / protocol)

**Example:**
- Target: multiple hosts downloading a malicious file from `bad.example.com`
- When: last 48 hours + 2 hours from now
- Supporting info: filenames/types `superbad.exe`, `new-crypto-miner.exe`
- Scope: `192.168.100.0/24`, protocols HTTP and FTP

#### 2. Diagnostic Analysis
> *"Clarifies the causes, effects, and interactions of conditions. Backward-looking view."*

**Steps:**
4. Capture network traffic (plug into relevant link, pull PCAP/netflow from SIEM)
5. Identify required network traffic components (filtering)
6. Understand captured network traffic

**Example:**
- Filter on `ftp-data` to find files transferred, reconstruct them
- Filter on `http.request.method == "GET"` to see GET requests matching filenames
- See who acquired files and other internal transfers

#### 3. Predictive Analysis
> *"Evaluates historical and current data, creates predictive model for future probabilities."*

**Steps:**
7. Note-taking and mind mapping (timeframes, suspicious hosts, conversations with timestamps/packet numbers)
8. Summary of analysis (what did we find?)

#### 4. Prescriptive Analysis
> *"Narrows down what actions to take to eliminate or prevent a future problem."*

- Decide what actions are required
- Prevent recurrence
- **Lessons learned** — document what worked, what didn't, what could improve

### The Full Workflow Template (memorize the 8 steps)

1. What is the issue?
2. Define scope and goal (what, which time period, supporting info)
3. Define targets (net / host(s) / protocol)
4. Capture network traffic
5. Identify required network traffic components (filtering)
6. Understand captured network traffic
7. Note-taking / mind mapping
8. Summary of analysis

> **Important:** This is **cyclic**, not once-and-done. You may need to rerun steps based on analysis of the original capture.

---

### ⏸️ RECALL BREAK — Chunk 3

Close the file. Answer:
1. What are the 4 types of analysis? (Name + one-sentence definition)
2. Which analysis type is "backward-looking"?
3. Which analysis type is about "lessons learned"?
4. List the 6 dependencies for active vs passive capture.
5. Why is a baseline important?

---

## 6. Chunk 4 — Analysis in Practice

> **Metaphor (Diffuse):** Think of yourself as a **triage nurse** in an emergency room. You don't examine every patient with the same depth. You start with the most common, obvious conditions (standard protocols), look for patterns (same time daily), notice unusual symptoms (host-to-host), and flag unique events.

### Key Components of Effective Analysis

#### 1. Know Your Environment
- Keep **asset inventories** and **network maps**
- If you don't know what belongs, you can't spot rogue assets

#### 2. Placement Is Key
- **Closest to the source of the issue** = ideal
- Internet traffic → listen to **inbound links**
- Isolated host → place capture tools in **same segment**

#### 3. Persistence
- Issues may be infrequent (C2 callbacks every few hours/days)
- Don't lose the drive to find the problem
- Could mean the difference between stopping an attacker and a ransomware attack

### Analysis Approach — The "Easy Wins"

> **Start with standard protocols first, then work into the austere and organization-specific.**

1. **Standard protocols first:**
   - HTTP/S, FTP, E-mail, basic TCP/UDP — most common from the world
   - Then: SSH, RDP, Telnet (cross-network comms)
   - Be mindful of security policy (should RDP be initiated outside enterprise? Telnet?)

2. **Look for patterns:**
   - Specific host(s) checking in with internet at same time daily
   - Typical **C2 profile** setup

3. **Check host-to-host within network:**
   - In standard setup, user hosts rarely talk to each other
   - Hosts talk to infrastructure (DNS, IP leases, enterprise services)
   - Host-to-host traffic → suspicious

4. **Look for unique events:**
   - Host changes browsing pattern
   - Different User-Agent string
   - Random port bound once or twice
   - Possible C2 callbacks, non-standard apps, abnormal behavior

5. **Don't be afraid to ask for help:**
   - Second set of eyes catches what you miss
   - After staring at captures, things blend together

### Scenario Walkthrough (from the module)

> You're a network admin at a large corp. A segment reports **high latency** and **new files on desktops**. You attach a computer, capture, and analyze.

**Without baseline:** You must examine every conversation, check hosts, determine rogue assets — daunting.

**With baseline:** Strip known-good. Use "top talkers" plugin. Look at connections between internal hosts or uncommon ports. See user hosts connecting on ports **8080 and 445** to each other — suspicious! Web traffic usually goes host → web server; SMB host → host is very suspicious. → Send a trouble ticket for potential breach.

> **Metaphor:** Baseline is the **"known good" background music**. When a wrong note plays, you hear it immediately.

---

### ⏸️ RECALL BREAK — Chunk 4

Close the file. Answer:
1. What are the 3 key components of effective analysis?
2. Why is placement "closest to the source" ideal?
3. List the 5 "easy wins" in the analysis approach.
4. Why is host-to-host SMB traffic suspicious?
5. Why is a baseline so powerful?

---

## 7. Chunk 5 — Tcpdump Fundamentals

> **Metaphor (Focused):** tcpdump is a **security camera** for your network interface. It records every frame, and its switches are the camera settings (zoom, resolution, which lens). The `pcap` file is the recording; the filters are how you review the footage.

### What Is Tcpdump?

- Command-line packet sniffer
- Built for Unix-like OSes (Windows twin: **WinDump** — discontinued; use WSL/Parrot/Ubuntu instead)
- Uses **libpcap** and **pcap** libraries
- Requires **promiscuous mode** to see all traffic on the segment
- Requires **root/sudo** (direct hardware access)
- Often preinstalled on Linux; found at `/usr/sbin/tcpdump`

### Install / Validate

```bash
which tcpdump                # locate
sudo apt install tcpdump     # install (if needed)
sudo tcpdump --version       # validate
```

### Basic Capture Switches (memorize these)

| Switch | Result |
|---|---|
| **-D** | List available interfaces |
| **-i** | Select interface (e.g., `-i eth0`) |
| **-n** | Don't convert addresses to names |
| **-nn** | Don't resolve IPs **or** ports |
| **-e** | Grab Ethernet header too |
| **-X** | Show contents in hex and ASCII |
| **-XX** | Same as X, plus Ethernet headers |
| **-v, -vv, -vvv** | Increase verbosity |
| **-c** | Grab N packets, then quit |
| **-s** | Define how much of a packet to grab |
| **-S** | Absolute sequence numbers (not relative) |
| **-q** | Print less protocol info |
| **-r file.pcap** | Read from file |
| **-w file.pcap** | Write to file |
| **-A** | ASCII only (not hex) |
| **-l** | Line-buffered output (for piping to grep) |

> **Tip:** `-S` is critical when comparing to logs — logs use absolute numbers. `-c`, `-n`, `-s`, `-S`, `-q` reduce data. `-v`, `-X`, `-e` add data.

### Common Command Examples

**List interfaces:**
```bash
sudo tcpdump -D
```

**Capture on interface:**
```bash
sudo tcpdump -i eth0
```

**Disable name resolution:**
```bash
sudo tcpdump -i eth0 -nn
```

**Show Ethernet header:**
```bash
sudo tcpdump -i eth0 -e
```

**Hex + ASCII output:**
```bash
sudo tcpdump -i eth0 -X
```

**Combine switches:**
```bash
sudo tcpdump -i eth0 -nnvXX
```

**Save to file:**
```bash
sudo tcpdump -i eth0 -w ~/output.pcap
```

**Read from file:**
```bash
sudo tcpdump -r ~/output.pcap
```

### Reading Tcpdump Output (memorize the fields)

```
11:15:40.321509 IP 172.16.146.2.57236 > ec2-99-80-22-207...https: Flags [P.], seq 2751910362:2751910399, ack 946558143, win 501, length 37
```

| Field | Color (module) | Meaning |
|---|---|---|
| **Timestamp** | Yellow | Time and date |
| **Protocol** | Orange | Upper-layer header (IP, etc.) |
| **Source & Destination IP.Port** | Orange | Format: `IP.port` |
| **Flags** | Green | TCP flags (S, S., P., F., etc.) |
| **Seq/Ack Numbers** | Red | Sequence/acknowledgment tracking |
| **Protocol Options** | Blue | Window size, MSS, selective ACKs, etc. |
| **Notes/Next Header** | White | Misc notes, dissector info (e.g., FTP) |

> **Flag shorthand:** `.` = ACK, `S` = SYN, `S.` = SYN-ACK, `P.` = PSH, `F.` = FIN, `R` = RST

### Practical Uses

> *"Theoretically, we can use tcpdump to create an IDS/IPS system by having a Bash script analyze the intercepted packets according to a specific pattern."* — e.g., ban an IP after too many ICMP echo requests.

---

### ⏸️ RECALL BREAK — Chunk 5

Close the file. Answer:
1. What library does tcpdump use?
2. What does `-i` do? `-nn`? `-e`? `-X`? `-w`? `-r`? `-S`?
3. Why do you need `sudo`?
4. In the output format, what does `Flags [S.]` mean?
5. What's the difference between `-n` and `-nn`?

---

## 8. Chunk 6 — Tcpdump Packet Filtering

> **Metaphor (Focused):** Filters are **search queries for the wire**. `host` is like searching a library catalog by author. `port` is searching by shelf number. `and`/`or`/`not` are Boolean glue. `less`/`greater` are size filters.

### Core Filters (memorize these)

| Filter | Result |
|---|---|
| **host** | Anything involving the host (bi-directional) |
| **src / dest** | Modifiers for source/destination host or port |
| **net** | Traffic sourcing/destined to a network (uses / notation) |
| **proto** | Specific protocol (ether, TCP, UDP, ICMP) |
| **port** | Bi-directional port filter |
| **portrange** | Range of ports (e.g., `0-1024`) |
| **less / greater** | Packet size filters (`< 64`, `> 500`) |
| **and / &&** | Both conditions must match |
| **or / \|\|** | Either condition matches |
| **not / !** | Anything but X |

> **Protocol numbers:** TCP=6, UDP=17, ICMP=1. `tcp` ≡ `proto 6`, `udp` ≡ `proto 17`.

### Filter Examples (memorize the patterns)

**Host filter:**
```bash
sudo tcpdump -i eth0 host 172.16.146.2
```

**Source filter:**
```bash
sudo tcpdump -i eth0 src host 172.16.146.2
```

**Source port:**
```bash
sudo tcpdump -i eth0 tcp src port 80
```

**Destination network:**
```bash
sudo tcpdump -i eth0 dest net 172.16.146.0/24
```

**UDP by name:**
```bash
sudo tcpdump -i eth0 udp
```

**UDP by number:**
```bash
sudo tcpdump -i eth0 proto 17
```

**Port filter:**
```bash
sudo tcpdump -i eth0 tcp port 443
```

**Port range:**
```bash
sudo tcpdump -i eth0 portrange 0-1024
```

**Size filters:**
```bash
sudo tcpdump -i eth0 less 64
sudo tcpdump -i eth0 greater 500
```

**AND:**
```bash
sudo tcpdump -i eth0 host 192.168.0.1 and port 23
```

**OR:**
```bash
sudo tcpdump -r sus.pcap icmp or host 172.16.146.1
```

**NOT:**
```bash
sudo tcpdump -r sus.pcap not icmp
```

### TCP Flags Filtering (Advanced)

To find packets with the **SYN** flag set:
```bash
tcpdump -i eth0 'tcp[13] &2 != 0'
```

> **How this works:** Count to the 13th byte in the TCP header structure, look at the 2nd bit. If it's 1 → SYN flag is ON.

### Pre-Capture vs Post-Capture Filtering

| Method | Effect |
|---|---|
| **Pre-capture** (filter during capture) | Drops non-matching traffic — reduces data, but may lose valuable evidence |
| **Post-capture** (filter when reading file) | Parses file, removes from output only — does **not** alter the file |

> **Best practice:** Capture wide, filter later — unless you know exactly what you need.

### Pro Tips

- **`-A`** → ASCII only (great for quickly spotting human-readable text)
- **`-l`** → line-buffered (pipe to `grep`)
- **`-S`** → absolute sequence numbers (match logs)
- **`-v`, `-X`, `-e`** → increase data
- **`-c`, `-n`, `-s`, `-S`, `-q`** → reduce data

**Pipe to grep:**
```bash
sudo tcpdump -Ar http.cap -l | grep 'mailto:*'
```

### Reference RFCs

| Link | Description |
|---|---|
| RFC 791 | IP |
| RFC 792 | ICMP |
| RFC 793 | TCP |
| RFC 768 | UDP |
| Wikipedia | RFC quick links |

---

### ⏸️ RECALL BREAK — Chunk 6

Close the file. Answer:
1. Write the filter to see only traffic to/from `10.0.0.5`.
2. Write the filter for TCP port 443.
3. Write the filter for anything **except** ICMP.
4. Write the filter for packets larger than 500 bytes.
5. What does `tcp[13] &2 != 0` find?
6. What's the difference between pre-capture and post-capture filtering?

---

## 9. Chunk 7 — Wireshark Basics

> **Metaphor (Diffuse):** Wireshark is the **CSI lab** of packet analysis. tcpdump is the field kit (fast, portable, CLI). Wireshark is the full forensic lab (GUI, dissectors, streams, exports). Same data, more power, more overhead.

### What Is Wireshark?

- Free, open-source **GUI** network traffic analyzer
- Multi-platform
- Captures live data off many interfaces (WiFi, USB, Bluetooth)
- Deep packet inspection for **hundreds** of protocols
- Decryption capabilities (IPsec, ISAKMP, Kerberos, SNMPv3, SSL/TLS, WEP, WPA/WPA2)

### Wireshark vs TShark

| Feature | TShark | Wireshark |
|---|---|---|
| Interface | Terminal (CLI) | GUI |
| Use case | Remote/headless, piping | Full visual analysis |
| Syntax | Shared with Wireshark | Shared with TShark |
| Best for | Automation, remote | Deep inspection, visual analysis |

### TShark Basic Switches

| Switch | Result |
|---|---|
| **-D** | List interfaces |
| **-L** | List link-layer mediums |
| **-i** | Interface to capture |
| **-f** | BPF capture filter |
| **-c** | Grab N packets |
| **-a** | Autostop (duration/size/packets) |
| **-r file** | Read from file |
| **-W file** | Write to pcapng |
| **-P** | Print summary while writing |
| **-x** | Hex + ASCII output |
| **-h** | Help |

**TShark examples:**
```bash
tshark -D
tshark -i 1 -w /tmp/test.pcap
tshark -i eth0 -f "host 172.16.146.2"
tshark -i eth0 -w /tmp/test.pcap -P
```

### Termshark

- **TUI** (Text User Interface) — Wireshark-like in your terminal
- Find it at: `github.com/gcla/termshark`
- Start with same strings as TShark/tcpdump
- Window opens when it senses traffic matching filter

### Wireshark GUI — The 3 Main Panes

```
┌─────────────────────────────────────────────────────────┐
│  TOOLBAR (capture, filter, save, analyze)               │
├─────────────────────────────────────────────────────────┤
│  PACKET LIST (Orange)                                   │
│  # │ Time │ Source │ Destination │ Protocol │ Info      │
├─────────────────────────────────────────────────────────┤
│  PACKET DETAILS (Blue)                                  │
│  ▸ Frame                                                │
│    ▸ Ethernet II                                        │
│      ▸ Internet Protocol                                │
│        ▸ Transmission Control Protocol                  │
│          ▸ HTTP                                         │
├─────────────────────────────────────────────────────────┤
│  PACKET BYTES (Green)                                   │
│  Hex + ASCII of selected field                          │
└─────────────────────────────────────────────────────────┘
```

**Packet List (Orange):**
- **Number** — order arrived
- **Time** — Unix time
- **Source** — source IP
- **Destination** — destination IP
- **Protocol** — TCP, UDP, DNS, etc.
- **Info** — summary of packet contents

**Packet Details (Blue):**
- Drill into protocols with greater detail
- Broken into chunks following OSI model
- Shown in **reverse** (lower layers at top)

**Packet Bytes (Green):**
- ASCII or hex output
- Selecting a field highlights its bytes
- Validates Wireshark's interpretation
- Each line: data offset + 16 hex bytes + 16 ASCII bytes

### Capture Filters vs Display Filters

| Feature | Capture Filters | Display Filters |
|---|---|---|
| Applied | Before capture | During/after capture |
| Syntax | **BPF** (same as tcpdump) | **Wireshark proprietary** |
| Effect | Drops non-matching traffic | Hides non-matching traffic (file unchanged) |
| Options | Fewer | Many more |
| Use case | Trim disk writes, troubleshoot one connection | Deep investigation, explore |

### Common Capture Filters (BPF)

| Filter | Result |
|---|---|
| `host x.x.x.x` | Only traffic to/from host |
| `net x.x.x.x/24` | Traffic to/from network |
| `src/dst net x.x.x.x/24` | Source/dest network only |
| `port #` | Only traffic on that port |
| `not port #` | Everything except port |
| `port # and #` | Both ports |
| `portrange x-x` | Ports in range |
| `ip / ether / tcp` | Specific protocol headers |
| `broadcast / multicast / unicast` | Specific traffic type |

### Common Display Filters (Wireshark)

| Filter | Result |
|---|---|
| `ip.addr == x.x.x.x` | Traffic to/from host (OR statement) |
| `ip.addr == x.x.x.x/24` | Traffic to/from network |
| `ip.src/dst == x.x.x.x` | Specific source/destination |
| `dns / tcp / ftp / arp / ip` | By protocol |
| `tcp.port == x` | Specific TCP port |
| `tcp.port / udp.port != x` | Exclude port |
| `and / or / not` | Boolean logic |

> **Critical distinction:** Port 80 ≠ HTTP. Ports are guidelines; protocols are behaviors. Filtering port 80 shows anything on that port. Filtering `http` shows GET/POST markers.

### Applying Filters in GUI

**Capture filter:**
1. Click **Capture** → **Options**
2. Select interface
3. Enter filter in "Capture filter for selected interfaces" box
4. Click **Start**

**Display filter:**
1. Click in the display filter toolbar at top
2. Type filter (turns **green** if valid)
3. Press Enter

> **Warning:** Large PCAPs can take seconds to minutes to process display filters. Break into chunks if needed.

---

### ⏸️ RECALL BREAK — Chunk 7

Close the file. Answer:
1. What are the 3 main panes of Wireshark, and what does each show?
2. What syntax do capture filters use? Display filters?
3. What's the effect of a capture filter on the file? A display filter?
4. Write a display filter for traffic to/from `192.168.1.10`.
5. Write a display filter for TCP port 443.
6. True or false: filtering port 80 is the same as filtering HTTP.

---

## 10. Chunk 8 — Wireshark Advanced Usage

> **Metaphor (Focused):** Wireshark's advanced features are **power tools** in the CSI lab. Following a TCP stream is **reassembling a shredded document**. Extracting objects is **lifting fingerprints**. Decrypting RDP is **opening a safe with the key you found**.

### The Statistics and Analyze Tabs

**Statistics tab** → detailed reports:
- Top talkers
- Specific conversations
- Breakdown by IP and protocol
- Protocol Hierarchy

**Analyze tab** → plugins:
- Follow TCP streams
- Filter on conversation types
- Prepare new packet filters
- Examine Expert Info

### Following TCP Streams

> *"Wireshark can stitch TCP packets back together to recreate the entire stream in a readable format. This ability also allows us to pull data (images, files, etc.) out of the capture."*

**Steps (GUI):**
1. Right-click a packet from the stream
2. Select **Follow → TCP**
3. New window shows entire stitched-together conversation

**Alternative (filter):**
```
tcp.stream eq #
```

> **What you'll see:** First 3 packets = full TCP handshake, then stream transfer. Filter clears everything else out of view.

### Extracting Data and Files from a Capture

**Requirements:** You must have captured the **entire conversation** (otherwise reassembly fails).

**Steps (GUI):**
1. Stop capture
2. **File → Export →** select protocol format (DICOM, HTTP, SMB, etc.)
3. Save files

> **Metaphor:** Wireshark reassembles the **shredded document** from its individual packets.

### FTP Analysis in Wireshark

**Key display filters:**

| Filter | Shows |
|---|---|
| `ftp` | Anything about FTP protocol |
| `ftp.request.command` | Commands on FTP control channel (port 21) — usernames, passwords, filenames |
| `ftp-data` | Data on FTP data channel (port 20) — actual files |

**Steps to dissect FTP data from a PCAP:**
1. Identify FTP traffic with `ftp`
2. Look at command controls with `ftp.request.command`
3. Choose a file, filter `ftp-data`, select packet, follow TCP stream
4. Change "**Show and save data as**" to "**Raw**"
5. Save as original file name
6. Validate the extraction (check file type)

### HTTP Object Extraction

**Filter for images:**
```
http && image-jfif
```

**Steps:**
1. Filter `http` to see HTTP traffic
2. Look for `200 OK` responses (server acknowledged a GET)
3. Follow TCP stream to verify file transfer
4. **File → Export Objects → HTTP → `file.JPG`**
5. Save locally

> **JFIF** = JPEG File Interchange Format. Look for it to confirm JPEG images.

### RDP Decryption (Preview — see Chunk 9)

**Filter for RDP:**
```
rdp
```

**Filter by port:**
```
tcp.port == 3389
```

**To decrypt:**
1. **Edit → Preferences → Protocols → TLS**
2. **Edit** by **RSA keys list** → new window
3. Add key: server IP, port `3389`, protocol `tpkt` or blank, key file `server.key`
4. Save and refresh

> **Why this works:** If you acquire the RDP certificate from the server, OpenSSL can extract the private key.

---

### ⏸️ RECALL BREAK — Chunk 8

Close the file. Answer:
1. What does "Follow TCP Stream" do?
2. What filter finds FTP control commands?
3. What filter finds FTP data transfers?
4. What filter finds JPEG images over HTTP?
5. Where in the GUI do you extract HTTP objects?
6. What must you have captured for file extraction to work?

---

## 11. Chunk 9 — RDP Decryption & Labs

> **Metaphor (Diffuse):** RDP decryption is like **finding the key to a safe**. The safe (RDP traffic) is encrypted with TLS. The key (RSA private key) is inside the server's certificate. Once you have the key, Wireshark can open the safe and show you everything.

### RDP Decryption Steps

**Filter for RDP:**
```
rdp
```
(May show nothing — RDP uses TLS by default.)

**Verify RDP exists via port:**
```
tcp.port == 3389
```

**Import the RSA key:**
1. **Edit → Preferences → Protocols → TLS**
2. Click **Edit** by **RSA keys list**
3. Click **+** to add a new key
4. **IP address:** `10.129.43.29` (RDP server)
5. **Port:** `3389`
6. **Protocol:** `tpkt` or blank
7. **Key file:** browse to `server.key`
8. Save and refresh the PCAP

**After import:**
- Filter `rdp` again → now shows decrypted RDP traffic
- Follow TCP streams, export objects, analyze PDUs

### RDP Analysis Questions (from the lab)

- **What host initiated the RDP session?** → Look at the first packet of the 3-way handshake (packet #8 in the example) → `10.129.43.27`
- **Which user account was used?** → Filter `tcp.port == 3389`, look for "Ignored Unknown Record," examine ASCII → shows the cookie/username

### Guided Lab: Traffic Analysis Workflow (Summary)

**Scenario:** Suspicious connection from Bob's host `172.16.10.90`.

**Workflow applied:**
1. **Issue:** Suspicious traffic from within network
2. **Scope:** Traffic originating from `10.129.43.4`, last 48 hours, file `NTA-guided.pcap`
3. **Targets:** `10.129.43.4` + anyone connected to it, unknown protocol over port 4444
4. **Capture:** Plug into `10.129.43.0/24` network; use provided PCAP
5. **Filtering:** Filter out anything not connected to `10.129.43.4`
6. **Understanding:**
   - **Conversations plugin:** 3 conversations, all related to suspicious host
   - **Protocol Hierarchy:** Mostly TCP, some UDP
   - **UDP first:** 9 packets (ARP, NAT, SSDP) — normal
   - **TCP:** `!udp && !arp` → all one conversation between `10.129.43.4` and `10.129.43.29`
   - **No teardown** — session still active, no RST
   - **Follow TCP stream** → alarm bells!
7. **Notes:**
   - Commands: `whoami`, `ipconfig`, `dir` (recon)
   - Account `hacker` created and added to `administrators` group
   - Plain text — Netcat shell
   - RDP from Bob's host to another Windows desktop
8. **Summary:** Malicious actor infiltrated at least one host. Recommend full IR.

### Lab Tips (from the module)

| Question | Tip |
|---|---|
| What traffic do I see? | Note protocols, ports, hosts |
| Is there more than one conversation? | Use Conversations plugin |
| How many unique hosts? | Use Conversations or Endpoints |
| Timestamp of first conversation? | Look at first full TCP handshake |
| What can I filter out? | Baseline traffic, broadcast, multicast |
| Who are the servers? | Answering on well-known ports (53, 80, 443) |
| What records were requested? | Look at protocol-specific info |

---

### ⏸️ RECALL BREAK — Chunk 9

Close the file. Answer:
1. What port does RDP use?
2. What must you have to decrypt RDP traffic?
3. Where in Wireshark do you import the RSA key?
4. In the guided lab, what commands did the attacker run?
5. What account did the attacker create?

---

## 12. Master Cheat Sheet

### TCP Flags Quick Reference

| Flag | Letter | Meaning |
|---|---|---|
| SYN | S | Synchronize (start connection) |
| ACK | . | Acknowledge |
| FIN | F | Finish (close connection) |
| RST | R | Reset (abort) |
| PSH | P | Push (deliver data) |
| URG | U | Urgent |

**Common combinations:**
- `[S]` = SYN
- `[S.]` = SYN-ACK
- `[.]` = ACK
- `[P.]` = PSH-ACK
- `[F.]` = FIN-ACK
- `[R.]` = RST-ACK

### Port Reference

| Port | Protocol | Transport |
|---|---|---|
| 20 | FTP data | TCP |
| 21 | FTP control | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 137/138 | NetBIOS | UDP |
| 139 | NetBIOS | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3389 | RDP | TCP |
| 8080 | HTTP alt | TCP |
| 8443 | HTTPS alt | TCP |

### tcpdump vs Wireshark vs TShark

| Aspect | tcpdump | TShark | Wireshark |
|---|---|---|---|
| Interface | CLI | CLI | GUI |
| Syntax | BPF | BPF + display | BPF + display |
| Best for | Quick captures, remote | Automation, remote | Deep visual analysis |
| Filters | Capture only | Capture + display | Capture + display |
| File format | pcap | pcapng | pcap/pcapng |

### Filter Syntax Comparison

| Purpose | tcpdump (BPF) | Wireshark Display |
|---|---|---|
| Host | `host 10.0.0.5` | `ip.addr == 10.0.0.5` |
| Source | `src host 10.0.0.5` | `ip.src == 10.0.0.5` |
| Destination | `dst host 10.0.0.5` | `ip.dst == 10.0.0.5` |
| Network | `net 10.0.0.0/24` | `ip.addr == 10.0.0.0/24` |
| Port | `port 443` | `tcp.port == 443` |
| Protocol | `tcp` / `udp` / `icmp` | `tcp` / `udp` / `icmp` |
| AND | `and` / `&&` | `and` / `&&` |
| OR | `or` / `\|\|` | `or` / `\|\|` |
| NOT | `not` / `!` | `not` / `!` |
| SYN flag | `tcp[13] &2 != 0` | `tcp.flags.syn == 1` |
| FTP commands | `port 21` | `ftp.request.command` |
| FTP data | `port 20` | `ftp-data` |
| HTTP GET | `tcp port 80` | `http.request.method == "GET"` |
| JPEG over HTTP | — | `http && image-jfif` |

### The NTA Workflow (One-Line Summary)

> **Ingest → Reduce Noise → Analyze → Detect → Fix & Monitor**

### The 4 Analysis Types (One-Line Each)

- **Descriptive:** What is the issue? Scope? Targets?
- **Diagnostic:** Capture, filter, understand — find the cause.
- **Predictive:** Note-taking, summary — predict future.
- **Prescriptive:** Decide actions, lessons learned.

### The 8-Step Workflow Template

1. What is the issue?
2. Define scope and goal
3. Define targets
4. Capture traffic
5. Filter (identify required components)
6. Understand traffic
7. Note-taking / mind mapping
8. Summary of analysis

### The 5 "Easy Wins" in Analysis

1. Standard protocols first
2. Look for patterns (C2 callbacks)
3. Check host-to-host traffic
4. Look for unique events
5. Ask for help

---

## 13. Spaced-Repetition Schedule

> **From *Learning How to Learn*:** "If you try to glue things into your memory by repeating something 20 times in one evening, it won't stick nearly as well as if you practice it the same number of times over several days."

| Day | Activity | Time |
|---|---|---|
| **Day 1** | Read Chunks 0–2, do recall breaks | 60 min |
| **Day 2** | Read Chunks 3–5, do recall breaks, **re-recall Chunks 0–2** | 60 min |
| **Day 3** | Read Chunks 6–7, do recall breaks, **re-recall Chunks 3–5** | 60 min |
| **Day 4** | Read Chunks 8–9, do recall breaks, **re-recall Chunks 6–7** | 60 min |
| **Day 5** | Master Cheat Sheet + Self-Test (§14) | 45 min |
| **Day 6** | **Interleaved practice problems** (below) | 45 min |
| **Day 7** | Rest / diffuse mode (walk, shower, sleep) | — |
| **Day 8** | Re-do self-tests, weak areas only | 30 min |
| **Day 14** | Full self-test again | 30 min |
| **Day 21** | Full self-test again | 30 min |
| **Day 30** | Full self-test again | 30 min |

> **Sleep is part of the schedule.** Do not skip it. Consolidation happens during sleep.

---

## 14. Interleaved Practice Problems

> **Interleaving** = mixing different problem types. This is deliberately harder than blocked practice, but it builds flexibility and creativity. **Do not peek at answers until you've tried.**

### Problem Set A — tcpdump Filters (Easy → Hard)

**A1.** Write a tcpdump filter to capture all traffic to/from `192.168.1.50`.

**A2.** Write a tcpdump filter to capture only TCP traffic on port 22.

**A3.** Write a tcpdump filter to capture all traffic **except** HTTP (port 80).

**A4.** Write a tcpdump filter to capture traffic from `10.0.0.0/8` destined for port 443.

**A5.** Write a tcpdump filter to capture packets larger than 1000 bytes.

**A6.** Write a tcpdump command to read `capture.pcap`, disable name resolution, show absolute sequence numbers, and display hex + ASCII.

**A7.** Write a tcpdump filter to find all SYN packets.

### Problem Set B — Wireshark Display Filters

**B1.** Write a display filter for traffic to/from `172.16.10.90`.

**B2.** Write a display filter for HTTP GET requests.

**B3.** Write a display filter for FTP control commands.

**B4.** Write a display filter for FTP data.

**B5.** Write a display filter for JPEG images over HTTP.

**B6.** Write a display filter to exclude ARP and UDP.

**B7.** Write a display filter for a specific TCP stream (stream #5).

### Problem Set C — Conceptual (Short Answer)

**C1.** What is the difference between a capture filter and a display filter?

**C2.** Why is host-to-host SMB traffic suspicious?

**C3.** What are the 4 types of analysis? Which is backward-looking?

**C4.** What are the 3 steps of the TCP handshake? Name the flags.

**C5.** What are the 3 steps of the TCP teardown? Name the flags.

**C6.** What port(s) does FTP use? What is each for?

**C7.** What is the difference between FTP active and passive mode?

**C8.** What is the NTA workflow? (5 steps)

**C9.** What are the 5 use cases of NTA?

**C10.** What are the 3 key components of effective analysis?

### Problem Set D — Scenario-Based (Hard Start, Jump to Easy)

> **Instruction:** Start with the hardest problem. If stuck for 1–2 minutes, switch to an easier one. Return later.

**D1.** You see many `SYN` packets on ports 1–1024 from a single host to many hosts. What is likely happening? What filter would you use to confirm?

**D2.** A user reports slow internet. You capture traffic and see many DNS requests from their host to `8.8.8.8` and `1.1.1.1`, with responses. What could be the issue? What would you check next?

**D3.** You see a host connecting to an external IP on port 4444 every 6 hours, with small amounts of data. What might this be? What analysis type applies?

**D4.** You find an FTP transfer of `secrets.txt` to an external IP. How would you extract the file from the PCAP? What filters would you use?

**D5.** You see a large cluster of SMB auth failures from one host to many. What might this indicate? What would you do next?

**D6.** You have an RDP capture and a `server.key` file. How do you decrypt the traffic? What filter do you use after decryption?

**D7.** You need to capture traffic from a specific VLAN. Your capture device is on a different VLAN. What can you do?

**D8.** You see HTTP traffic on port 8080. Is this normal? How do you confirm it's actually HTTP?

### Problem Set E — Lab-Style (Full Workflow)

**E1.** You are given `NTA-guided.pcap`. Follow the 8-step workflow. Write:
- Issue
- Scope (what, when, supporting info)
- Targets
- Filtering approach
- What you found
- Summary

**E2.** You are given `rdp.pcapng` and `server.key`. Decrypt the RDP traffic. Answer:
- What host initiated the RDP session?
- What user account was used?
- What did the user do in the session?

---

## 14. Self-Test Answer Keys

### Problem Set A Answers

**A1.** `host 192.168.1.50`

**A2.** `tcp port 22`

**A3.** `not port 80` (or `not tcp port 80`)

**A4.** `src net 10.0.0.0/8 and dst port 443`

**A5.** `greater 1000`

**A6.** `tcpdump -nnSXr capture.pcap`

**A7.** `tcp[13] &2 != 0`

### Problem Set B Answers

**B1.** `ip.addr == 172.16.10.90`

**B2.** `http.request.method == "GET"`

**B3.** `ftp.request.command`

**B4.** `ftp-data`

**B5.** `http && image-jfif`

**B6.** `!arp && !udp`

**B7.** `tcp.stream eq 5`

### Problem Set C Answers

**C1.** Capture filters apply **before** capture and drop non-matching traffic (file is smaller). Display filters apply **during/after** capture and hide non-matching traffic from view (file is unchanged). Capture filters use BPF; display filters use Wireshark syntax.

**C2.** In a standard setup, user hosts rarely talk to each other. Hosts talk to infrastructure (DNS, IP leases, enterprise services). Host-to-host SMB could indicate lateral movement, credential theft, or malware spreading.

**C3.** Descriptive, Diagnostic, Predictive, Prescriptive. **Diagnostic** is backward-looking (tries to find reasons for events).

**C4.** SYN → SYN-ACK → ACK. Flags: SYN, SYN+ACK, ACK.

**C5.** FIN-ACK → FIN-ACK → ACK. Flags: FIN+ACK, FIN+ACK, ACK.

**C6.** Port 20 (data transfer), Port 21 (control commands). Both TCP.

**C7.** Active (default): server listens for `PORT` command from client, stating which port to use for data. Passive: client sends `PASV`, server responds with IP + port for data channel. Passive is for clients behind firewalls/NAT.

**C8.** Ingest → Reduce Noise → Analyze → Detect → Fix & Monitor.

**C9.** Collecting, Setting baseline, Identifying (non-standard ports, suspicious hosts), Detecting (malware on wire), Investigating (past incidents, threat hunting).

**C10.** Know your environment (asset inventories, network maps), Placement (closest to source), Persistence (issues may be infrequent).

### Problem Set D Answers

**D1.** Likely a **portscan**. Filter: `tcp[13] &2 != 0` (SYN packets) + `host <suspect>` to see the scan pattern.

**D2.** DNS resolution issues or DNS tunneling. Check: Are the DNS requests for unusual domains? Are responses coming back? Is the user's host talking to many different IPs? Check for **DNS tunneling** (large TXT records, unusual query patterns).

**D3.** Likely a **Command and Control (C2) callback**. Small data every 6 hours = beaconing. **Predictive analysis** applies (look for patterns, predict future occurrences).

**D4.** Filters: `ftp` → `ftp.request.command` (see `RETR secrets.txt`) → `ftp-data` → select packet → Follow TCP Stream → change to "Raw" → save as `secrets.txt`. Validate file type.

**D5.** **SMB auth failures** cluster = credential theft / lateral movement attempt. Next: Identify source host, check if any auth succeeded, check what resources were accessed, quarantine host if compromised.

**D6.** **Edit → Preferences → Protocols → TLS → Edit RSA keys list → + → IP: server IP, Port: 3389, Protocol: tpkt, Key file: server.key → Save → Refresh.** After decryption, filter: `rdp` or `tcp.port == 3389`.

**D7.** Use a **SPAN port** (port mirroring) on the switch, or a **network tap**. Connect capture device to the mirrored port. Alternatively, use a device with multiple NICs.

**D8.** **Not necessarily normal**, but ports are guidelines. To confirm it's HTTP, filter on `http` (which looks for GET/POST markers, etc.) rather than `tcp.port == 8080`. Check the payload for HTTP methods/headers.

### Problem Set E Answers

**E1.** (Your answers will vary based on the actual PCAP, but here is the expected structure.)
- **Issue:** Suspicious traffic from within the network.
- **Scope:** Traffic from `10.129.43.4`; last 48 hours; file `NTA-guided.pcap`.
- **Targets:** `10.129.43.4` and anyone connected to it; unknown protocol over port 4444.
- **Filtering:** Filter out anything not connected to `10.129.43.4`. Use Conversations plugin and Protocol Hierarchy.
- **Found:** Three conversations, all related to suspicious host. Mostly TCP, some UDP. UDP traffic (ARP, NAT, SSDP) is normal. TCP traffic is all one conversation between `10.129.43.4` and `10.129.43.29`. No teardown → session still active. Following the TCP stream reveals: `whoami`, `ipconfig`, `dir` (recon), and creation of user `hacker` added to `administrators` group. Plain text — Netcat shell.
- **Summary:** Malicious actor infiltrated at least one host. Recommend full IR procedure.

**E2.** (Your answers will vary, but based on the module's example.)
- **Host that initiated:** `10.129.43.27` (first packet of the 3-way handshake, packet #8).
- **User account:** Look at `tcp.port == 3389` filter, find "Ignored Unknown Record," examine ASCII → shows the cookie/username.
- **What user did:** Depends on the specific PCAP — follow TCP streams, export objects, analyze RDP PDUs.

---

## 15. Final Self-Test (Comprehensive)

> **Instructions:** Close this file. Answer all 20 questions in 20 minutes. This is your "exam." If you score below 16/20, review the relevant chunks and retest in 24 hours.

1. What does NTA stand for and what is its purpose?
2. List the 5 use cases of NTA.
3. List the 5 steps of the NTA workflow.
4. What is the difference between passive and active capture?
5. What are the 4 types of analysis? Which is backward-looking?
6. What are the 3 steps of the TCP handshake? Name the flags.
7. What are the 3 steps of the TCP teardown? Name the flags.
8. What port(s) does FTP use? What is each for?
9. What port does SMB use (modern)?
10. What port does RDP use?
11. What library does tcpdump use?
12. Write a tcpdump filter for traffic to/from `10.1.1.5`.
13. Write a Wireshark display filter for HTTP GET requests.
14. What is the difference between a capture filter and a display filter?
15. What does `tcp[13] &2 != 0` find?
16. What filter finds FTP data in Wireshark?
17. What filter finds JPEG images over HTTP?
18. What must you have to decrypt RDP traffic?
19. What are the 5 "easy wins" in analysis?
20. Why is host-to-host SMB traffic suspicious?

**Scoring:**
- 18–20: Excellent — you're ready to start the module labs.
- 16–17: Good — review the ones you missed.
- 13–15: Review the relevant chunks and retest in 24 hours.
- Below 13: Re-read all chunks, do the recall breaks again, and retest in 48 hours.

---

## 16. Final Words (from *Learning How to Learn*)

> *"Learning is so vitally important to our future... In this course, we've tried to give you a better sense of the learning process. ... You have not truly learned something unless you can teach it to others. Teach those ideas to others and you will find that they will continue to resonate and deepen in your own mind."* — Dr. Terrence Sejnowski

> *"Many people believe that what they're initially naturally good at is what they're supposed to be doing in life. But I myself am living proof that passions can broaden, change, and grow. The world is evolving and a broad tool kit that allows you to learn effectively in many different subject areas is one of the most powerful assets you can have."* — Dr. Barbara Oakley

> *"Best of luck in your life of learning."*

---

**End of Study Guide.** Now close this file, take a walk, and let your diffuse mode do its work. Then come back and do the self-test.