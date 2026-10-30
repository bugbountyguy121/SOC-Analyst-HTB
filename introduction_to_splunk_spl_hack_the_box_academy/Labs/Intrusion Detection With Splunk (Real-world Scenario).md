


![Pasted image 20261029110813.png](../../Attathemnts/Pasted%20image%2020261029110813.png)


![mermaid-diagram.png](../../Attathemnts/mermaid-diagram.png)




First of all started by discovering the source events 

```

index="main" earliest=0

```


![Pasted image 20261029114611.png](../../Attathemnts/Pasted%20image%2020261029114611.png)




Lest Hunt after wineventlog:sysmon

Next we are gong to run 
What this is doing is that we are hunting after [Sysmon Event ID 10 - ProcessAccess](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010): Useful for spotting remote code injection and memory dumping, as it records when handles on processes are made.

```
index="main" EventCode=10 lsass
| stats count by SourceImage
```


Relation ship  :

![Pasted image 20261029115003.png](../../Attathemnts/Pasted%20image%2020261029115003.png)



![Pasted image 20261029115120.png](../../Attathemnts/Pasted%20image%2020261029115120.png)



![Pasted image 20261029115222.png](../../Attathemnts/Pasted%20image%2020261029115222.png)


> But don't immediately select the first row. A rare process can be perfectly legitimate, while a frequently observed process can still be compromised.



Wowwww i just spot it i was trying to start with the lowest count but if you focus a bit you are going to see that their is tow Source image of runddl32.exe and i've said maybe its the same thing and the data is not clean but if you look closer its :



System32\rundll32.exe and system32\rundll32.exe 

Did you saw it ?

S != s






> [!NOTE] Not from Ai explaining :

You were about to treat them as two different entries, then stopped and compared the strings character by character. That is excellent investigative thinking.

You have just discovered an important distinction:

*Different text values do not necessarily mean different processes or different files.*


Finally found it by modifying the SPL they gave us in the notes section

```
index="main" EventCode=10 lsass CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace

```




# Splunk — UNKNOWN CallTrace Alert Tuning

> [!abstract] Purpose
> Understand how the HTB lesson turns a broad hunt for `UNKNOWN` call-trace segments into a more focused **candidate alert** for suspicious process access. This note explains what each filter removes, why it is used, what evidence it preserves, and what blind spots it can introduce.
>
> **Core principle:** every exclusion is a noise-reduction hypothesis, not proof that the excluded activity is safe.

## 1. The investigation in one sentence

Find Sysmon process-access events whose call trace contains `UNKNOWN`, identify legitimate sources of that pattern (especially JIT/runtime activity), progressively suppress known noisy cases, then inspect the remaining source/target/call-trace combinations before creating an alert.

## 2. Mind map — the complete detection logic

```mermaid

```

## 3. Flowchart — why each filter is applied

```mermaid
flowchart TD
    A[Start: all searchable events] --> B[Filter CallTrace containing UNKNOWN]
    B --> C[Group by EventCode]
    C --> D{Which event type contains UNKNOWN?}
    D -->|HTB dataset: EventCode 10| E[Focus on Sysmon ProcessAccess]
    D -->|Other event types| X[Investigate their meaning separately]
    E --> F[Group by SourceImage]
    F --> G[Review frequent and rare source processes]
    G --> H[Remove SourceImage = TargetImage]
    H --> I[Why? Focus on cross-process access, not self-access]
    I --> J[Exclude Microsoft.NET source paths]
    J --> K[Exclude ni.dll and clr.dll call-trace matches]
    K --> L[Why? Reduce known JIT/runtime-generated UNKNOWN noise]
    L --> M[Exclude wow64 call-trace matches]
    M --> N[Why? Reduce compatibility-layer call-trace noise]
    N --> O[Exclude Explorer.exe]
    O --> P[Why? Highly versatile process; difficult baseline; high noise]
    P --> Q[Group by SourceImage, TargetImage, CallTrace]
    Q --> R[Inspect remaining evidence manually]
    R --> S{Is suspicious behavior corroborated?}
    S -->|No / uncertain| T[Refine hypothesis; inspect events and benign explanations]
    T --> R
    S -->|Yes| U[Build, test, document and monitor candidate alert]

    classDef start fill:#172554,stroke:#60A5FA,color:#FFFFFF
    classDef filter fill:#134E4A,stroke:#5EEAD4,color:#FFFFFF
    classDef reason fill:#3F2A63,stroke:#C4B5FD,color:#FFFFFF
    classDef decision fill:#78350F,stroke:#FBBF24,color:#FFFFFF
    classDef outcome fill:#14532D,stroke:#86EFAC,color:#FFFFFF
    class A,B,C,E,F,G,Q,R start
    class H,J,K,M,O filter
    class I,L,N,P reason
    class D,S decision
    class T,U outcome
```

## 4. The evidence: what does `UNKNOWN` mean?

Sysmon **Event ID 10 — ProcessAccess** records one process opening/accessing another process. The lesson investigates the `CallTrace` field, which contains stack/call-path context associated with the access.

A call trace containing `UNKNOWN` can indicate that part of the call path comes from memory that does not map cleanly to a known file-backed image. Shellcode or injected code can execute from such memory, so this can be suspicious.

But:

- `UNKNOWN` does **not** automatically mean shellcode.
- JIT compilers deliberately generate executable code in memory at runtime.
- Some compatibility/runtime mechanisms can also produce call-trace segments that are not straightforwardly mapped to a normal file path.
- Event ID 10 says a process accessed another process; it does not, by itself, prove a successful LSASS dump or credential theft.

**Analyst interpretation:** `UNKNOWN` is a useful hunting clue. It needs context and corroboration before it becomes a high-confidence detection.

## 5. Query progression — each stage and its purpose

### Stage 1 — Find which event types contain `UNKNOWN`

```spl
index="main" CallTrace="*UNKNOWN*"
| stats count by EventCode
```

**Grammar**

- `index="main"`: select the dataset.
- `CallTrace="*UNKNOWN*"`: keep events where the `CallTrace` field contains the text `UNKNOWN`.
- `|`: pass matching events into the next pipeline command.
- `stats count by EventCode`: count matching events per event code.

**HTB observation:** the lesson reports 1,575 matching events, all under EventCode 10 in this dataset. That is why the investigation focuses on Sysmon ProcessAccess. This is a result from the HTB lab, not a universal rule for every Splunk environment.

### Stage 2 — See which processes are generating the events

```spl
index="main" CallTrace="*UNKNOWN*"
| stats count by SourceImage
```

`SourceImage` identifies the process that initiated access. Grouping by it gives a manageable list of process paths and counts.

**Why do this?** You cannot manually inspect 1,575 raw events efficiently. First summarize by source process, then select candidates for deeper review.

**Important:** rare does not equal malicious; common does not equal safe. Frequency is prioritization context, not a verdict.

### Stage 3 — Exclude self-access

```spl
index="main" CallTrace="*UNKNOWN*"
| where SourceImage!=TargetImage
| stats count by SourceImage
```

**What it removes:** events where the source process and target process are the same according to these fields.

**Why:** this hunt is interested in a process accessing a *different* process. Self-access is not the behavior being prioritized in this particular detection idea, so removing it reduces irrelevant records.

**What it does not prove:** self-access is not universally harmless. This is a scope choice for this hunt, not a general rule that same-process events can never matter.

### Stage 4 — Reduce .NET / CLR JIT noise

```spl
index="main" CallTrace="*UNKNOWN*"
SourceImage!="*Microsoft.NET*"
CallTrace!=*ni.dll*
CallTrace!=*clr.dll*
| where SourceImage!=TargetImage
| stats count by SourceImage
```

There are three exclusions here, and they address related but distinct clues.

| Exclusion | What it filters | Why the lesson filters it |
|---|---|---|
| `SourceImage!="*Microsoft.NET*"` | Source process paths containing `Microsoft.NET` | The lesson identifies .NET/JIT activity as a source of legitimate `UNKNOWN` call-trace noise. |
| `CallTrace!=*ni.dll*` | Call traces containing `ni.dll` | The lesson treats this as related to .NET native-image/JIT behavior and excludes it to improve alert fidelity. |
| `CallTrace!=*clr.dll*` | Call traces containing `clr.dll` | `clr.dll` is associated with the .NET Common Language Runtime; runtime/JIT activity can produce legitimate call-trace patterns. |

**JIT in plain English:** Just-In-Time compilation turns managed/intermediate code into machine code while a program is running. That generated code lives in memory. Since it may not correspond to an ordinary standalone executable image on disk, memory/call-stack telemetry can contain regions that look `UNKNOWN` to a file-backed module lookup.

**Why exclude these?** The objective is to avoid alerting on a known class of legitimate runtime behavior every time it produces an `UNKNOWN` call-trace segment. This reduces false positives and alert fatigue.

**Caution:** these are broad string/path exclusions. A malicious process can use .NET, and a process running from a .NET directory is not automatically benign. Excluding the whole category can hide malicious activity that abuses the runtime. The lesson chooses a simplified, higher-fidelity filter for its lab dataset; a production detection should validate the exact runtime behavior and scope exclusions narrowly.

### Stage 5 — Exclude WOW64-related call traces

```spl
index="main" CallTrace="*UNKNOWN*"
SourceImage!="*Microsoft.NET*"
CallTrace!=*ni.dll*
CallTrace!=*clr.dll*
CallTrace!=*wow64*
| where SourceImage!=TargetImage
| stats count by SourceImage
```

**What it filters:** events whose `CallTrace` contains `wow64`.

**Why the lesson filters it:** WOW64 is the Windows compatibility mechanism that allows 32-bit applications to run on 64-bit Windows. Its transition/compatibility paths can involve memory/call-trace regions that are not represented like ordinary file-backed modules. The lesson treats these as another source of `UNKNOWN` noise and mentions a possible relationship to Heaven's Gate.

**Important nuance:** the lesson presents this as a hunt-tuning explanation, not proof that every WOW64-related `UNKNOWN` segment is benign or that Heaven's Gate is occurring. Treat the exclusion as a lab heuristic. Attackers can operate through compatibility layers too, so a blanket exclusion can create a blind spot.

### Stage 6 — Exclude Explorer.exe

```spl
index="main" CallTrace="*UNKNOWN*"
SourceImage!="*Microsoft.NET*"
CallTrace!=*ni.dll*
CallTrace!=*clr.dll*
CallTrace!=*wow64*
SourceImage!="C:\\Windows\\Explorer.EXE"
| where SourceImage!=TargetImage
| stats count by SourceImage
```

**What it filters:** events where the source process is the specified Windows Explorer executable path.

**Why the lesson filters it:** Explorer is a general-purpose Windows shell process. It participates in many types of normal user and system activity, and many tools interact with it. That makes its behavior broad and difficult to baseline using this simple `UNKNOWN` call-trace rule. Keeping every Explorer-related match would add substantial noise and make the remaining candidates harder to review.

**Caution:** Explorer is not inherently safe. Attackers can inject into, abuse, or run code through legitimate Windows processes. Excluding Explorer entirely makes the alert quieter but also means this specific alert will not catch suspicious activity sourced from that path. In production, consider a narrower exception based on verified benign behavior rather than excluding the process wholesale.

### Stage 7 — Review the remaining combinations, not only the process name

```
index="main" CallTrace="*UNKNOWN*"
SourceImage!="*Microsoft.NET*"
CallTrace!=*ni.dll*
CallTrace!=*clr.dll*
CallTrace!=*wow64*
SourceImage!="C:\\Windows\\Explorer.EXE"
| where SourceImage!=TargetImage
| stats count by SourceImage, TargetImage, CallTrace
```

**Why add `TargetImage` and `CallTrace` back?**

A list grouped only by `SourceImage` tells you which source process generated matches. It does not show the target of each access or the call-trace pattern associated with it. Grouping by all three preserves more investigative context:

- `SourceImage`: who initiated the access?
- `TargetImage`: which process was accessed?
- `CallTrace`: what call-path evidence was recorded?
- `count`: how often did that particular combination occur?

This is still an aggregation. It does not preserve every original event field or prove maliciousness. Use a focused detail search to inspect raw event samples for a suspicious combination.

## 6. Mind map — the reason behind every exclusion

```mermaid
flowchart LR
    U[UNKNOWN in CallTrace] --> N[Possible unbacked code]
    N --> J[JIT / runtime noise]
    N --> W[WOW64 compatibility noise]
    N --> S[Self-access not the focus]
    N --> E[Explorer is broad and noisy]

    J --> J1[Exclude Microsoft.NET source paths]
    J --> J2[Exclude ni.dll matches]
    J --> J3[Exclude clr.dll matches]
    W --> W1[Exclude wow64 matches]
    S --> S1[SourceImage != TargetImage]
    E --> E1[Exclude specified Explorer.exe path]

    J1 --> R[Smaller candidate set]
    J2 --> R
    J3 --> R
    W1 --> R
    S1 --> R
    E1 --> R
    R --> V[Validate remaining source + target + call trace]

    classDef clue fill:#172554,stroke:#60A5FA,color:#FFFFFF
    classDef noise fill:#3F2A63,stroke:#C4B5FD,color:#FFFFFF
    classDef filter fill:#134E4A,stroke:#5EEAD4,color:#FFFFFF
    classDef validate fill:#78350F,stroke:#FBBF24,color:#FFFFFF
    class U,N clue
    class J,W,S,E noise
    class J1,J2,J3,W1,S1,E1 filter
    class R,V validate
```

## 7. Why do we exclude anything at all?

The goal is to balance two competing outcomes:

| Detection outcome | Meaning | Operational impact |
|---|---|---|
| True positive | Suspicious activity is alerted | Analyst investigates a real threat. |
| False positive | Benign activity is alerted | Analyst time is wasted; alert fatigue grows. |
| False negative | Malicious activity is filtered out or not detected | Threat activity may go unnoticed. |
| True negative | Benign activity is correctly not alerted | Alert queue stays focused. |

The exclusions aim to reduce false positives. But every exclusion can increase false negatives if attackers use the excluded process, runtime, or call-trace pattern.

> [!important] The trade-off
> A quieter alert is not automatically a better alert. A high-fidelity rule must still detect the malicious behaviors it was designed to catch. Always measure what the exclusions remove, not just how many alerts remain.

## 8. How could an attacker bypass this rule?

The HTB lesson gives one explicit example: an attacker could load a DLL whose name ends with `NI`, causing the call trace to contain a string that matches the `ni.dll` exclusion pattern. Because the filter is based on a substring, the event could be excluded even though the DLL is not a trusted .NET native image.

General detection-engineering lessons:

1. **String exclusions are brittle.** A name can be chosen to resemble a trusted module or contain an excluded substring.
2. **Path exclusions are brittle.** An attacker may run from an excluded location or abuse a legitimate process that is excluded.
3. **Process-name exclusions are brittle.** A trusted executable can be abused; a familiar name does not guarantee trusted behavior.
4. **A single telemetry signal is incomplete.** `UNKNOWN` alone is not proof of shellcode, and absence of `UNKNOWN` does not prove no injection occurred.
5. **Over-tuning can hide the threat.** Every added exception needs a documented reason, owner, scope, and review date.

### How to strengthen the logic

- Prefer specific, verified module identities and expected paths over loose substring matches where the telemetry supports it.
- Correlate the access event with process creation, process identity, user, host, parent process, command line, target process, and timestamp.
- Where available, use process GUIDs and process IDs to tie activity to a process instance rather than relying only on executable names.
- Maintain an allowlist of known-good behavior with narrow scope (specific signer, path, version, host role, or parent-child relationship) rather than broad process-name exclusions.
- Test the alert against known benign JIT/runtime activity **and** known malicious examples.
- Review excluded events periodically; legitimate software and attacker techniques change.

## 9. What this query is — and what it is not

**It is:** a lab-scale candidate detection based on process-access events with `UNKNOWN` call-trace segments, followed by exclusions intended to suppress known noisy patterns.

**It is not:** a universal LSASS-dumping detector, proof of shellcode, proof of credential theft, or a production-ready rule that can be deployed without validation.

Before promoting it to an alert, answer:

- What exact behavior are we detecting?
- Which event source and fields must be present?
- Which known benign cases are excluded, and why?
- What malicious cases might the exclusions hide?
- What evidence will an analyst see when the alert fires?
- How will we test and maintain the rule?

## 10. Analyst memory hook

```text
UNKNOWN ≠ malicious
UNKNOWN = investigate

JIT / CLR / ni.dll  → possible legitimate generated code
WOW64               → possible compatibility-layer noise
SourceImage=TargetImage → not the cross-process behavior prioritized here
Explorer.exe        → broad behavior, difficult baseline

Exclude to reduce noise.
Validate to avoid blind spots.
```

## 11. SPL grammar reminders for this hunt

| Syntax | Meaning in this investigation |
|---|---|
| `CallTrace="*UNKNOWN*"` | Keep events whose CallTrace contains `UNKNOWN`. |
| `SourceImage!="*Microsoft.NET*"` | Exclude source paths matching the Microsoft.NET pattern. |
| `CallTrace!=*ni.dll*` | Exclude call traces matching the `ni.dll` substring pattern. |
| `CallTrace!=*clr.dll*` | Exclude call traces matching the `clr.dll` substring pattern. |
| `CallTrace!=*wow64*` | Exclude call traces matching the `wow64` substring pattern. |
| `SourceImage!="C:\\Windows\\Explorer.EXE"` | Exclude the specified Explorer source path. |
| `where SourceImage!=TargetImage` | Compare two field values and keep events where they differ. |
| `stats count by A, B, C` | Group by the combination of fields and count events in each group. |

> [!tip] Query debugging
> Add one exclusion at a time. After each edit, compare the number of events and inspect a few removed samples. If an exclusion removes both known-benign and known-malicious examples, it is too broad for the intended purpose.

## 12. Final analyst workflow

1. Start broad enough to discover where `UNKNOWN` appears.
2. Identify the relevant event type and understand its semantics.
3. Group by source process to prioritize the work.
4. Add one exclusion at a time, based on a specific benign explanation.
5. Inspect what each exclusion removes.
6. Reintroduce source, target, and call-trace context.
7. Validate raw events and correlate with other telemetry.
8. Only then convert the hunt into an alert with documented limitations.

**The core skill is not knowing which strings to exclude. It is being able to explain what each exclusion is trying to remove, what evidence supports that decision, and what attack activity might disappear with it.**



![mermaid-diagram 1.png](../../Attathemnts/mermaid-diagram%201.png)

![Pasted image 20261030085835.png](../../Attathemnts/Pasted%20image%2020261030085835.png)


rundll32.exe

by using :


```
index="main" EventCode=10 lsass SourceImage= *rundll32.exe*
| table _time host Image ImageLoaded ProcessId CallTrace
| sort 0 _time
```

I was able to reterive a lot of misused dlls 


![Pasted image 20261030085012.png](../../Attathemnts/Pasted%20image%2020261030085012.png)



```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=7 Image="*rundll32.exe" lsass
| table _time host ProcessId ProcessGuid Image ImageLoaded
| sort 0 - _time
```

![Pasted image 20261030085416.png](../../Attathemnts/Pasted%20image%2020261030085416.png)








---

---






![Pasted image 20261030155751.png](../../Attathemnts/Pasted%20image%2020261030155751.png)



![Pasted image 20261030155758.png](../../Attathemnts/Pasted%20image%2020261030155758.png)



![mermaid-diagram(1).png](../../Attathemnts/mermaid-diagram(1).png)





It's going to be something like this : 


```
index="main" EventCode=7 ImageLoaded="*clr.dll*"
| stats count by Image
| sort 0 + count
```






![Pasted image 20261030161657.png](../../Attathemnts/Pasted%20image%2020261030161657.png)




```
Image = C:\Users\waldo\Downloads\SharpHound.exe
```




Now we are going to run this : 

```
index="main" (EventCode=1 OR EventCode=5)
Image="*SharpHound.exe"
| table _time host EventCode Image ProcessGuid ProcessId ParentImage CommandLine
| sort 0 _time
```


![Pasted image 20261030162504.png](../../Attathemnts/Pasted%20image%2020261030162504.png)




![Pasted image 20261030162642.png](../../Attathemnts/Pasted%20image%2020261030162642.png)







```
index="main" EventCode=1 ParentImage="*randomfile.exe*"
| table _time ComputerName User Image CommandLine

```




