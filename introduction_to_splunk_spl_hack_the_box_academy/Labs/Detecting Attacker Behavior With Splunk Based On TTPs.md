



![Pasted image 20261102122825.png](../../Attathemnts/Pasted%20image%2020261102122825.png)


From our previous investigation, we already saw this command in your Sysmon results:

```
psexec64.exe \\10.0.0.47 -u waldo -p Password@123 hostname
```

![mermaid-diagram 2.png](../../Attathemnts/mermaid-diagram%202.png)




![Pasted image 20261102123007.png](../../Attathemnts/Pasted%20image%2020261102123007.png)


![Pasted image 20261102154209.png](../../Attathemnts/Pasted%20image%2020261102154209.png)

---
title: Sysmon Event 8 — Detecting Thread Injection Outliers
tags:
  - HTB-Academy
  - SOC
  - Splunk
  - Sysmon
  - detection
created: 2026-11-02
source: "Understanding Log Sources & Investigating with Splunk — Section 5"
---

# Detecting Thread Injection Outliers (Sysmon Event 8)

## 🎯 The Concept

> [!info] What is Event ID 8?
> **`CreateRemoteThread`** — a process creates a thread **inside another process**.
> Attackers use this for **process injection** to hide malicious code inside a legitimate process.

| Field | Meaning |
|---|---|
| `SourceImage` | The process **creating** the thread (the injector) |
| `TargetImage` | The process **receiving** the thread (the victim) |
| `NewThreadId` | The thread ID created |

> [!tip] Why statistics?
> Normal systems create *some* remote threads. A process creating an **abnormally high number** is a statistical outlier → strong injection candidate.

---

## ❓ The Question

> Find the **source process image** creating an unusually high number of threads in other processes.
> **Rule:** number of injected threads **> 2 standard deviations above the average**.
> **Answer format:** `_.exe`

---

## 🔍 The SPL Query

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8
| bin _time span=1h
| stats count as thread_count by _time, SourceImage
| eventstats avg(thread_count) as avg_count, stdev(thread_count) as stddev_count
| eval threshold = avg_count + (2 * stddev_count)
| where thread_count > threshold
| sort - thread_count
| table _time, SourceImage, thread_count, avg_count, stddev_count, threshold

```


