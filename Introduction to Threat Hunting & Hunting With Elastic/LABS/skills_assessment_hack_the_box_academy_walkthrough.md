---
title: Skills Assessment | Hack The Box Academy (Walkthrough)
source: ""
exported: 2026-10-25T23:36:14.924Z
tags:
  - htb
  - walkthrough
---
# Skills Assessment | Hack The Box Academy (Walkthrough)

Source: 
Exported: 2026-10-25T23:36:14.924Z
Pages exported: 1

# Skills Assessment - Walkthrough

Source: https://academy.hackthebox.com/app/module/214/section/2287

# Skills Assessment

* * *

## Hunting For Stuxbot (Round 2)

Recently uncovered details shed light on the operational strategy of Stuxbot's newest iteration.

1.  The newest iterations of Stuxbot are exploiting the `C:\Users\Public` directory as a conduit for deploying supplementary utilities.
2.  The newest iterations of Stuxbot are utilizing registry run keys as a mechanism to ensure their sustained presence within the infected system.
3.  The newest iterations of Stuxbot are utilizing PowerShell Remoting for lateral movement within the network and to gain access to domain controllers.

* * *

## The Available Data

The cybersecurity strategy implemented is predicated on the utilization of the Elastic stack as a SIEM solution. Through the "Discover" functionality we can see logs from multiple sources. These sources include:

-   `Windows audit logs` (categorized under the index pattern windows\*)
-   `System Monitor (Sysmon) logs` (also falling under the index pattern windows\*, more about Sysmon [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon))
-   `PowerShell logs` (indexed under windows\* as well, more about PowerShell logs [here](https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html))
-   `Zeek logs`, [a network security monitoring tool](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-zeek.html) (classified under the index pattern zeek\*)

* * *

## The Tasks

Navigate to the bottom of this section and click on `Click here to spawn the target system!`

Now, navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Discover". Then, click on the calendar icon, specify "last 15 years", and click on "Apply".

`Hunt 1`: Create a KQL query to hunt for ["Lateral Tool Transfer"](https://attack.mitre.org/techniques/T1570/) to `C:\Users\Public`. Enter the content of the `user.name` field in the document that is related to a transferred tool that starts with "r" as your answer.



![Pasted image 20261026003717.png](../../Attathemnts/Pasted%20image%2020261026003717.png)






`Hunt 2`: Create a KQL query to hunt for ["Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"](https://attack.mitre.org/techniques/T1547/001/). Enter the content of the `registry.value` field in the document that is related to the first registry-based persistence action as your answer.

`Hunt 3`: Create a KQL query to hunt for ["PowerShell Remoting for Lateral Movement"](https://www.ired.team/offensive-security/lateral-movement/t1028-winrm-for-lateral-movement). Enter the content of the `winlog.user.name` field in the document that is related to PowerShell remoting-based lateral movement towards DC1.

* * *


![Pasted image 20261026104112.png](../../Attathemnts/Pasted%20image%2020261026104112.png)


---


---

tags:

- SOC
    
- KQL
    
- Threat-Hunting
    
- HTB
    

---

# 🔎 KQL Hunting Cheat Sheet

> [!tip] The core rule  
> **Search → Inspect → Correlate → Validate → Extract**
> 
> Build your query from evidence, not guesses.

## 1. Wildcards & Quotes

The `*` wildcard matches **zero or more characters**. In KQL, it only works as a wildcard when it is **outside quotation marks**.

|Pattern|Meaning|
|---|---|
|`process.name: powershell*`|Starts with `powershell`|
|`process.name: *powershell*`|Contains `powershell`|
|`process.name: "powershell*"`|Looks for a literal `*`|

> [!important] Windows paths  
> Backslashes are special characters in KQL. Escape literal backslashes with `\\` when using an unquoted pattern.

**Example — find Registry Run paths:**

```
registry.path: *\\CurrentVersion\\Run*
```

## 2. Combine Conditions

Use `AND` when both conditions must match the same document. Use `OR` when either condition can match.

**Registry value-set events:**

```
event.code: 13
```

**Narrow to relevant Registry paths:**

```
registry.path: *\\CurrentVersion\\Run*
```

**Combine after testing both conditions:**

```
event.code: 13 AND registry.path: *\\CurrentVersion\\Run*
```

> [!warning] Zero results?  
> Check the field name, field type, time range, actual document values, and wildcard escaping. Test each condition independently before combining them.

## 3. SOC Hunt Methodology

1. **Understand the technique** — Read the MITRE ATT&CK description. Identify the attacker behavior and expected telemetry.
    
2. **Identify the fields** — Find the fields that describe the action, target, user, process, and timestamp.
    
3. **Start broad** — Search using one strong indicator. Inspect real documents.
    
4. **Refine gradually** — Add filters only when you understand what each one excludes.
    
5. **Validate** — Confirm that the event actually represents the behavior in the question.
    
6. **Extract** — Open the correct document and read the exact requested field.
    

## 4. Fields to Investigate

|Field|Purpose|
|---|---|
|`@timestamp`|When did it happen?|
|`host.name`|Which host recorded the event?|
|`event.code`|Event identifier, if populated|
|`winlog.event_id`|Windows event identifier, if populated|
|`registry.path`|Which Registry location?|
|`registry.value`|Which Registry value name?|
|`registry.data.strings`|What data is stored in the value?|
|`process.name`|Which process?|
|`process.command_line`|What command was executed?|
|`winlog.user.name`|Which account is associated with the event?|

> [!note] Field names depend on the dataset  
> `event.code` and `winlog.event_id` are not interchangeable assumptions. Inspect the available fields and documents before choosing one.

## 5. Special Case: Find the _First_ Action

When the hunt asks for the **first persistence action**:

1. Find matching events.
    
2. Verify their Registry paths and behavior.
    
3. Compare `@timestamp` values.
    
4. Identify the earliest valid action.
    
5. Open that document and extract the requested field.
    

**Never assume the first displayed result is the earliest event.** Check Kibana's sort order and the active time range.

---

**Reference:** [Elastic — KQL syntax and wildcards](https://www.elastic.co/docs/reference/query-languages/kql)



by searching for the targeted path wish we got frome mitre attack 

![Pasted image 20261026111430.png](../../Attathemnts/Pasted%20image%2020261026111430.png)



![Pasted image 20261026111632.png](../../Attathemnts/Pasted%20image%2020261026111632.png)






---

title: "KQL Hunting & Field Discovery — SOC Quick Reference"  
tags:

- SOC
    
- KQL
    
- Threat-Hunting
    
- PowerShell
    
- HTB
    

---

# 🔎 KQL Hunting & Field Discovery

> [!tip] The core methodology  
> **Behavior → Telemetry → Event ID → Field → Filter → Validate → Extract**
> 
> Don't memorize every field. Learn how to discover which field contains the evidence you need.

## 1. Understand the Hunt

**Example objective:** Detect PowerShell remoting for lateral movement towards `DC1` and extract `winlog.user.name`.

Translate the question into evidence requirements:

|Question|Evidence to investigate|
|---|---|
|What technology?|PowerShell|
|What behavior?|Remote session or command|
|Which target?|`DC1`|
|Which event?|PowerShell script-block logging, such as Event ID `4104`|
|Which answer field?|`winlog.user.name`|

> [!important] Don't confuse the answer field with the search field  
> `winlog.user.name` is the field you ultimately need to extract. It is not necessarily the field you should use to discover the remoting activity.

## 2. Understand the Query

```
winlog.event_id: "4104" AND powershell.file.script_block_text: *DC1*
```

|Component|Meaning|
|---|---|
|`winlog.event_id`|Field containing the Windows event ID|
|`:`|Matches the specified value or pattern|
|`"4104"`|PowerShell Script Block Logging event|
|`AND`|Both conditions must match the same document|
|`powershell.file.script_block_text`|Field intended to contain the PowerShell script-block text|
|`*DC1*`|Matches text containing `DC1`, with any characters before or after it|

**Why Event ID 4104?** When Script Block Logging is enabled, PowerShell records the content of script blocks it processes. This can expose commands and scripts relevant to an investigation.

Reference: [Microsoft — PowerShell logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging)

## 3. Discover Fields Instead of Guessing

### Step 1 — Find the event type

Start with a broad query:

```
winlog.event_id: "4104"
```

Inspect the matching documents. Confirm their event provider, channel, and contents.

### Step 2 — Inspect a document's source

In Kibana Discover:

1. Expand a result using the arrow beside its row.
    
2. Inspect the document's JSON or expanded fields.
    
3. Search the Available fields panel for terms such as `script`, `powershell`, `message`, or `user`.
    
4. Identify which field contains the actual script content.
    

### Step 3 — Test whether the field exists

```
powershell.file.script_block_text: *
```

Here, `field: *` searches for documents where the field has an indexed value.

If no results appear, don't blindly change the query. Verify that the field exists in your dataset and inspect the actual document source for an alternative field name.

### Step 4 — Search for the target

Once you've verified the field:

```
winlog.event_id: "4104" AND powershell.file.script_block_text: *DC1*
```

Inspect the returned script text for evidence of remoting towards `DC1`.

Useful additional clues include:

- `Enter-PSSession`
    
- `New-PSSession`
    
- `Invoke-Command`
    
- `-ComputerName`
    

These are investigation clues, not required strings in every event.

> [!warning] Field names depend on the dataset  
> `powershell.file.script_block_text` is a schema-specific field path. If it is not available, use the field actually present in your documents. Don't assume every Windows dataset has identical mappings.

## 4. Extract the Answer Correctly

After identifying the document associated with the remoting activity:

1. Open that exact document.
    
2. Locate `winlog.user.name`.
    
3. Copy its value exactly as displayed.
    
4. Submit the value, not your KQL query.
    

> [!important] Same-document rule  
> The target evidence and the requested user field must come from the relevant event document. Don't take a username from an unrelated PowerShell event.

## 5. Common Mistakes

> [!failure] Searching the wrong evidence  
> Searching `powershell.command.invocation_details.related_command: *` can return PowerShell activity without proving that it involves remoting or `DC1`.

> [!failure] Confusing Event ID 800 with 4104  
> The earlier event you examined was Event ID `800`, labelled **Pipeline Execution Details**, containing `Add-Type`. It was useful telemetry, but it did not by itself establish remoting towards `DC1`.

> [!failure] Assuming the user from another hunt  
> Don't reuse an account from a previous investigation unless evidence or the task explicitly connects the hunts.

> [!failure] Over-filtering too early  
> Start broad, inspect the documents, and add one condition at a time. A narrow query can hide relevant events if your assumptions are wrong.

## 6. Reusable SOC Investigation Checklist

- What exact behavior does the hunt describe?
    
- Which telemetry source records that behavior?
    
- Which event ID or event type is relevant?
    
- Which field contains the evidence I need to search?
    
- Have I inspected a real document to verify the field?
    
- Does my query identify the correct target and behavior?
    
- Have I validated the matching document?
    
- Did I extract the requested field from that exact document?
    

---

### Field Discovery Formula

**What happened?** → Identify the behavior.

**Where is it logged?** → Identify the telemetry and event type.

**Where is the evidence stored?** → Inspect the document and field mapping.

**What should I filter for?** → Search for a distinctive clue such as a target hostname or command.

**What should I submit?** → Extract the requested field from the validated event.

**Reference:** [Elastic — KQL syntax and wildcards](https://www.elastic.co/docs/reference/query-languages/kql)





![Pasted image 20261026115354.png](../../Attathemnts/Pasted%20image%2020261026115354.png)