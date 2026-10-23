---
dg-publish: true
---









---



a comprehensive search can be initiated based on [Sysmon Event ID 15](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015) (FileCreateStreamHash), which represents a browser file download event. We're assuming that a potentially malicious OneNote file was downloaded from Gmail, our organization's email provider.


---



When i saw this :
![Pasted image 20261023151528.png](../../Attathemnts/Pasted%20image%2020261023151528.png)


i wasn't able to do the same config even that i had a part of the module wish covers this but you really need to keep this with u :


> [!important] Important Reference
> [Winlogbeat Exported Fields: Process (Elastic Docs)](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-process)




### Inspecting Field Values (The "Sneak Peek")

Before you add a field to your table or write a query, you can see what kind of data it actually holds.

- **How to Use It:** Simply click on any field name in the sidebar.
    
- **What it Shows:** A popup will appear showing the top 10 most frequent values for that specific field in your current time range, along with the percentage of occurrence. This is an incredibly fast way to spot anomalies or see if a field contains the exact data (like a specific IP address or file name) you are hunting for.






# 🔍 SIEM Logic: Linking Events to Processes & Building Aggregations

## 1. The Logical Link: Actions vs. Actors
When you hunt in a SIEM, data fields are not isolated; they tell a chronological story of cause and effect. 

If you search for `event.code:15 AND file.name:*invoice.one`, you are finding the **Action** (a file was downloaded). But as an analyst, you must immediately ask: *Who or what performed this action?*

This is where `process.executable` comes in. It identifies the **Actor**.
*   **`event.code:15`** = The system registered a "FileCreateStreamHash" event (a file dropped from the internet).
*   **`file.name`** = The victim (`invoice.one`).
*   **`process.executable`** = The suspect that created the file. 

If `process.executable` is `C:\Program Files\Google\Chrome\Application\chrome.exe`, it means the user manually downloaded it via a web browser. If `process.executable` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, it means a script downloaded the file invisibly in the background—a massive red flag indicating malicious automation. You *always* need the actor to understand the context of the action.

---

## 2. Replicating the Visual Hierarchy (Kibana Lens)

The image you are looking at is not the standard "Discover" tab. The menu showing "Rows" and "Top values of..." indicates you are in **Kibana Lens**[cite: 3], building a Data Table visualization. 

This setup groups data hierarchically (like nested folders) from the broadest category down to the exact timestamp.

### How to Replicate This View Exactly:
1. Navigate to **Dashboard** or **Visualize Library** in Kibana and select **Create visualization** -> **Lens**.
2. Set the visualization type (top middle dropdown) to **Data Table**.
3. Look at the configuration panel on the right side. Under the **Rows** section[cite: 3], you will drag and drop fields from the left sidebar or click the **(+) Add** button to stack them in this exact order:
    *   **Row 1:** Add `event.type` (Function: Top values). This categorizes the broad nature of the event (e.g., `creation`, `change`, `start`)[cite: 3].
    *   **Row 2:** Add `event.code` (Function: Top values). This breaks the type down into the specific Sysmon Event ID (e.g., `1`, `11`, `15`)[cite: 3].
    *   **Row 3:** Add `event.action` (Function: Top values). This provides the human-readable description of the code (e.g., `Process creation`, `File created`)[cite: 3].
    *   **Row 4:** Add `process.executable` (Function: Top values). This identifies the exact program path executing the action[cite: 3].
    *   **Row 5:** Add `@timestamp` (Function: Date Histogram or Top values). This pins the exact time the event occurred[cite: 3].

### Why build it this way?
By stacking the rows in this order[cite: 3], you force the table to aggregate the data logically. Instead of reading 10,000 raw logs, your table will group all identical events together, showing you a clean summary of what processes are causing what actions across your entire environment.

> [!tip] Quick Search Strategy
> In the Discover tab, you can search `process.executable:*` to filter your view to *only* show logs where an executing process is recorded, stripping out background noise before you even start hunting.


![Pasted image 20261023154701.png](../../Attathemnts/Pasted%20image%2020261023154701.png)



C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe



![Pasted image 20261023155253.png](../../Attathemnts/Pasted%20image%2020261023155253.png)


C:\Users\bob\Downloads\invoice.one:Zone.Identifier


![Pasted image 20261023155437.png](../../Attathemnts/Pasted%20image%2020261023155437.png)



HTB is not for copy paste you gotta focus and change almost every thing huh :

This is the date you should focus on 

They  said As part of our search process, since we're interested in DNS names, we'd like to display only the `dns.question.name` field in the result table. Please note the specified time `March 26th 2023 @ 22:05:00` to `March 26th 2023 @ 22:05:48` 
but if you check you are going to find that this is the real date : - 2023-03-26 20:05:43.609
