



![Pasted image 20261027173025.png](../../Attathemnts/Pasted%20image%2020261027173025.png)


![Pasted image 20261027173040.png](../../Attathemnts/Pasted%20image%2020261027173040.png)


Im smiling hahaha their is not hing like just keep clicking here and their and understand the app 

![Pasted image 20261027173545.png](../../Attathemnts/Pasted%20image%2020261027173545.png)


This is the net view command 

```
`sysmon` process=net.exe (CommandLine="net  view") | stats count by Computer,CommandLine
```


Lets try to make some changes on this 


```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
| stats count by ParentImage, Image
| sort - count
```



```
sourcetype= "sysmon" process=net.exe (CommandLine="net view") | stats count by Computer_CommandLine
```


I was wrong and by using Ai im trying to figure out how to solve this 

i thought they already gave me the broken command and  i need to fix it but their is a logic lost behind it 
![Pasted image 20261027174647.png](../../Attathemnts/Pasted%20image%2020261027174647.png)

# Splunk + Sysmon: Finding a Command Without Guessing





> **Goal:** Recover what actually executed from event evidence, then repair the saved report. Don't invent missing values from the answer format.

![Splunk_Command_Hunt_Mindset.gif](../../Attathemnts/Splunk_Command_Hunt_Mindset.gif)

## The investigation mindset

1. **Translate the question into evidence.** Here, the thing to prove is the complete command line recorded for a process.
    
2. **Discover broadly, narrow with evidence.** Start with a useful phrase, then verify the index, sourcetype, event type, and field names. Every filter should have a reason.
    
3. **Inspect a raw event.** Common Sysmon process-creation fields include `Image` (executable path), `CommandLine` (command + arguments), `ParentImage` (parent executable), and often `EventCode` (event ID). Confirm which ones your Splunk data actually has. Sysmon Event ID `1` commonly represents process creation.
    
4. **Build the query one condition at a time.** A nonexistent field, wrong sourcetype, or exact-match condition that is too narrow can silently remove the event you need.
    
5. **Preserve raw evidence before summarizing.** `table` helps display fields; `stats` groups and aggregates events, which may hide row-level command details.
    
6. **Validate the saved report.** Compare its SPL to the known-good event, correct the smallest wrong assumption, rerun it, and read the full `CommandLine` value. The final answer should come from that value, not a guess.
    

## SPL pipeline: what each part does

```
index="main" "net view"
```

This is a **discovery search** to find candidate events. If it returns nothing useful, check the index and available data before assuming the command was never logged.

```
 | table _time, Image, CommandLine
```

The `|` passes the current results into another command. `table` displays selected fields, assuming those fields exist in the events.

```
... | stats count by ComputerName, CommandLine
```

`stats` creates a grouped summary. `count` counts events; `by` groups by the listed fields. `ComputerName, CommandLine` means **two field names**. A name like `Computer_CommandLine` means one field with that exact name; the underscore does not automatically combine fields.

## Tiny glossary

- **Index:** The Splunk data set being searched.
    
- **Sourcetype:** Classification/format label assigned to incoming events; inspect it rather than assuming its name.
    
- **Field:** A named value extracted from an event.
    
- **Filter:** A condition that keeps matching events.
    
- **Pipe (**`**|**`**):** Sends results to the next SPL command.
    
- `**CommandLine**`**:** Often the best evidence for the executable's arguments.
    

## Before saving the report — checklist

- Does the result contain the relevant process-creation event?
    
- Did I verify the actual sourcetype and field names?
    
- Is the command-line condition broad enough to find the full value?
    
- Did I inspect the returned event before using `stats`?
    
- Does the repaired report return the evidence needed to answer the question?
    

**Rule to remember:** A search result is evidence; an assumption is only a hypothesis. Make the data earn every filter.

Finally :


![Pasted image 20261027175938.png](../../Attathemnts/Pasted%20image%2020261027175938.png)



![Pasted image 20261027180000.png](../../Attathemnts/Pasted%20image%2020261027180000.png)




![Pasted image 20261027181253.png](../../Attathemnts/Pasted%20image%2020261027181253.png)



![Pasted image 20261027181155.png](../../Attathemnts/Pasted%20image%2020261027181155.png)



Lets work on this :


```
`sysmon` EventCode=3 Image="$imgsel$" protocol="$protosel$" dest_port="$portsel$" "$destinations$" | eval Destination=coalesce(dest_host,dest_ip) | stats count, values(Destination) AS "Destinations", values(dest_port) AS "Ports", values(protocol) AS "Protocols" by Image | fields Image Destinations Ports Protocols count
```


By using :


```
index="main" | stats count by sourcetype | sort - count
```


![Pasted image 20261028080915.png](../../Attathemnts/Pasted%20image%2020261028080915.png)


```
sourcetype="WinEventLog:Security" | table *
```

Then click to expand several events. Ask:
- Is this really the source/type I intended?
- What does `_raw` contain?
- Which fields are extracted?
- Are values complete paths or only filenames?
- Is the computer represented by `host`, `ComputerName`, or another field?
- Are the event codes present and in the format I expect?
- Is this a sample of the time range or a complete view?


I've got a  lot of info 


![Pasted image 20261028081411.png](../../Attathemnts/Pasted%20image%2020261028081411.png)




```
EventCode=3
| stats count by sourcetype
```


interesting :

```
EventCode=3  sourcetype="WinEventLog:Sysmon"
```







![Pasted image 20261028082552.png](../../Attathemnts/Pasted%20image%2020261028082552.png)




Finally 


![Pasted image 20261028083735.png](../../Attathemnts/Pasted%20image%2020261028083735.png)


```
EventCode=3  sourcetype="WinEventLog:Sysmon" 
|  search Image = *SharpHound.exe*
```


# Splunk SPL — Quick Syntax Rules

> **Mental model:** Find the right events → check the fields → process the results → verify the output.

## 1. Basic query shape

```
index="main" EventCode=3 Image="*SharpHound.exe*"
| table _time, Image, ComputerName
| sort - _time
```

- **Before `|`**: choose the index and filter matching events.
- **After `|`**: put a command that processes the current results.
- **Each `|`**: passes output to the next command.

## 2. Core language rules

|Rule|Example|Meaning|
|---|---|---|
|Filter on fields|`EventCode=3 Image="*net.exe*"`|Conditions separated by spaces normally act like **AND**.|
|Alternatives|`EventCode=1 OR EventCode=3`|Match either event code.|
|Partial match|`Image="*SharpHound.exe*"`|`*` matches any text before/after the filename.|
|Group logic|`(EventCode=1 OR EventCode=3) Image="*net.exe*"`|Apply the image filter to either event code.|
|Pipe to a command|`|search Image="_net.exe_"`|
|Name an output|`count AS event_count`|`AS` gives a calculated result a readable name.|

**Remember:** a syntactically valid field/value filter can still return nothing if the field or value doesn't match your dataset. Verify field names in actual events.

## 3. Commands worth knowing first

|Goal|Pattern|Result|
|---|---|---|
|Inspect evidence|`|table _time, Image, CommandLine`|
|Count all matches|`|stats count`|
|Count by field|`|stats count by Image`|
|Count unique values|`|stats dc(ComputerName) AS unique_computers`|
|Create a field|`|eval duration = last_time - first_time`|
|Filter results|`|where duration < 600`|
|Sort descending|`|sort - count`|

- `search` filters using search syntax; `where` evaluates expressions, such as comparing two fields or checking a calculated number.
- `stats` summarizes events. After it runs, original event fields usually disappear unless they're used in the grouping or aggregations.
- `AS` names outputs; you choose descriptive aliases like `event_count` or `duration_seconds`. The source fields, such as `Image` and `_time`, must be discovered in the events.

## 4. Debug a failed search

1. **Source:** right index and time range?
2. **Event:** right event ID / activity?
3. **Fields:** do the field names and values actually exist?
4. **Filters:** did a condition exclude the events?
5. **Pipeline:** is each `|` followed by a valid command?
6. **Output:** does the result answer the question, or did `stats` hide details you need?

## Reusable starter templates

**Inspect first:**

```
index="<index>" <event filters>
| table _time, <field_1>, <field_2>
```

**Count by a field:**

```
index="<index>" <event filters>
| stats count by <group_field>
| sort - count
```

Replace placeholders with verified values. Add one stage at a time and inspect the output before continuing.


