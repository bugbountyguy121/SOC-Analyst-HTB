# 📘 HTB Skills Assessment – Splunk Investigation Notes

```markdown
---
title: HTB Skills Assessment – Log Sources & Splunk
course: Understanding Log Sources & Investigating with Splunk
section: 6 / 6 – Skills Assessment
status: in-progress
tags:
  - HTB
  - Splunk
  - Sysmon
  - blue-team
  - skills-assessment
created: 2026-11-02
target: 10.129.59.174 (ACADEMY-SFUND-SPLUNK)
---
```

> [!info] Scenario
> Continue from **Intrusion Detection With Splunk (Real-world Scenario)**. Reconstruct the missing attack chain and identify the malicious process that started the infection.

> [!todo] Lab Setup
> - [ ] Spawn target system
> - [ ] Open `http://[Target IP]:8000`
> - [ ] Launch **Search & Reporting** app in Splunk
> - [ ] Confirm data is flowing in `index=*`

---

## 🧩 1. Grammar Breakdown of HTB Questions

HTB questions are **compound imperative sentences**:

> *"Navigate to…, open…, and find… the process that…"*

| Grammar Part | Example | Meaning for You |
|---|---|---|
| **Imperative verbs** | Navigate, open, find | Do these actions in order |
| **Prepositional phrase** | "through SPL searches against all data" | Search broadly first; don't over-filter |
| **Noun + relative clause** | "the process **that created remote threads in rundll32.exe**" | The answer is a **process name**; the clause defines the evidence condition |
| **Answer format** | `_.exe` | `_` is a placeholder → **one filename ending in `.exe`** |

### 🔹 Q1 – Plain Grammar Translation
> Find **[the process]** that **[created remote threads]** in **[rundll32.exe]**.

- "process" → **source** process
- "created remote threads" → Sysmon **Event ID 8 / CreateRemoteThread**
- "in rundll32.exe" → **target image** is `rundll32.exe`

### 🔹 Q2 – Plain Grammar Translation
> Find **[the process]** that **[started the infection]**.

- "process" → executable name
- "started the infection" → earliest/parent process in the chain
- Pivot from Q1 → look at **process creation** / parent-child relationships

---

## 📏 2. Answer Format Rules

> [!warning] Format Checklist
> - [ ] Answer is **one filename only**
> - [ ] Ends in **`.exe`**
> - [ ] No full path
> - [ ] No quotes
> - [ ] No PID / no `SourceImage=`
> - [ ] Keep exact spelling/case from Splunk
> - [ ] `_.exe` → replace `_`, keep `.exe`

**Template**

```text
Answer Q1: <filename>.exe
Answer Q2: <filename>.exe
```

**Shape example (not the real answer)**

```text
Answer Q1: example.exe
Answer Q2: example.exe
```

---

## 🔍 3. Q1 Worksheet – Fill It In Yourself

![Pasted image 20261102202251.png](../../Attathemnts/Pasted%20image%2020261102202251.png)


> [!question] Q1
> Find the process that created remote threads in `rundll32.exe`. Format: `_.exe`

### Step A – Search Broadly

```
index=* EventCode=8 TargetImage="*rundll32.exe"
| stats count by SourceImage, TargetImage
```


![Pasted image 20261102202200.png](../../Attathemnts/Pasted%20image%2020261102202200.png)


If empty, loosen:

```spl
index=* "rundll32.exe"
| stats count by EventCode, SourceImage, TargetImage
```

### Step B – Identify the Field

- `SourceImage` → process that performed the injection
- `TargetImage` → process injected into

### Step C – Reasoning Notes

```text
Q1 evidence:
- Event code: ______
- TargetImage: ______
- SourceImage: ______
- Therefore the process that created remote threads in rundll32.exe is: ______.exe
```

### Step D – Final Answer

```text
Q1 answer: ______.exe
```

---

## 🩺 4. Q2 Worksheet – Fill It In Yourself


![Pasted image 20261102202313.png](../../Attathemnts/Pasted%20image%2020261102202313.png)



```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8 TargetImage=*rundll32.exe
| stats count by SourceImage, TargetImage
```
> [!question] Q2
> Find the process that started the infection. Format: `_.exe`

> [!tip] Method
> Trace **backward** from Q1 — don't copy Q1's answer directly.

### Step A – Pivot From Q1

```spl
index=* EventCode=1 Image="*<Q1_PROCESS_NAME>.exe"
| table _time ParentImage Image CommandLine User
```

### Step B – Inspect `rundll32.exe` Parent

```
index=* EventCode=1 Image="*rundll32.exe"
| table _time ParentImage Image CommandLine User
```

### Step C – Build the Chain

```text
Process chain notes:
1. Earliest suspicious process: ______.exe
2. It spawned: ______.exe
3. That process led to rundll32.exe / injection: yes/no
4. The process that "started the infection" is: ______.exe
```

### Step D – Final Answer

```text
Q2 answer: ______.exe
```

---

## 📝 5. Combined Note Template

> [!example] Copy-Paste Working Notes
> ```text
> Q1
> - Question type: find the process
> - Condition: created remote threads
> - Target: rundll32.exe
> - SPL used: ______________________
> - SourceImage found: ______________________
> - Final answer: ______________________.exe
>
> Q2
> - Question type: find the process that started infection
> - Method: pivot from Q1 / inspect parent of rundll32.exe
> - SPL used: ______________________
> - ParentImage / earliest process found: ______________________
> - Final answer: ______________________.exe
> ```

---

## ⚠️ 6. Grammar Rule to Remember While Answering

> [!warning] Read the format literally
> **"Answer format: `_.exe`"** means:
>
> - ✅ `something.exe`
> - ❌ `C:\Windows\something.exe`
> - ❌ `something`
> - ❌ `SourceImage=something.exe`
> - ❌ `something.exe (PID 1234)`

**Final answer = filename only.**

---

## 🔗 Related Notes

- [Sysmon Event IDs Cheatsheet](Sysmon%20Event%20IDs%20Cheatsheet.md)
- [Splunk SPL Basics](Splunk%20SPL%20Basics.md)
- [Intrusion Detection With Splunk (Real-world Scenario)](./Intrusion%20Detection%20With%20Splunk%20(Real-world%20Scenario).md)
- [Process Injection Techniques](Process%20Injection%20Techniques.md)

---

## 🏷️ Tags

`#HTB` `#Splunk` `#Sysmon` `#BlueTeam` `#SkillsAssessment` `#ProcessInjection` `#EDR`

---

> [!success] Next Action
> Run the Q1 SPL search, paste the `SourceImage` / `ParentImage` / `Image` rows back here, and we'll verify your reasoning together — **you** write the final filename.


