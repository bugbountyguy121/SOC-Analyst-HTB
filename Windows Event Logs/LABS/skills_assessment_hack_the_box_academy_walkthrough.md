---
title: Skills Assessment | Hack The Box Academy (Walkthrough)
source: ""
exported: 2026-10-22T14:34:44.107Z
tags:
  - htb
  - walkthrough
---
# Skills Assessment | Hack The Box Academy (Walkthrough)

Source: 
Exported: 2026-10-22T14:34:44.108Z
Pages exported: 1

# Skills Assessment - Walkthrough

Source: https://academy.hackthebox.com/app/module/216/section/2303

# Skills Assessment

To keep you sharp, your SOC manager has assigned you the task of analyzing older attack logs and providing answers to specific questions.

Navigate to the bottom of this section and click on `Click here to spawn the target system!`



![Pasted image 20261022153553.png](../../Attathemnts/Pasted%20image%2020261022153553.png)



As you can see we can't filter the Event ID 7 : 
![Pasted image 20261022153811.png](../../Attathemnts/Pasted%20image%2020261022153811.png)


We need to reconfigure sysmon for that :

![Pasted image 20261022154350.png](../../Attathemnts/Pasted%20image%2020261022154350.png)


What may take you 3 days to learn you can do it latter in 5 min 
![Pasted image 20261022154706.png](../../Attathemnts/Pasted%20image%2020261022154706.png)


I have a big question:
We had almost 1566 entries how we can search all of them if we dont know that its already named  winnet.dll
+ what if the attacker changed its name?

![Pasted image 20261022163101.png](../../Attathemnts/Pasted%20image%2020261022163101.png)

![Pasted image 20261022163221.png](../../Attathemnts/Pasted%20image%2020261022163221.png)





  

# 🛡️ Hunting DLL Hijacking via Path Anomaly (Behavioral Approach)

> [!abstract] The Core Concept (Why this works)
> 
>   
> 
> - **The application dictates the name:** An attacker cannot name their malicious DLL whatever they want. They must name it exactly what the vulnerable `.exe` is blindly requesting. _Therefore, hunting for a specific DLL name is a flawed strategy._
>     
>       
>     
> - **Path Anomaly is the weakness:** Legitimate core DLLs live in protected system folders (e.g., `C:\Windows\System32`). To successfully hijack the execution flow, the attacker **must** drop their fake DLL into an unprotected, user-writable directory (like `\Temp\`, `\Downloads\`, or `\AppData\`) right next to the vulnerable application.
>     
>       
>     

## 🗺️ Visual Hunt Map

Extrait de code

```
graph TD
    A[Start: Query Sysmon Event ID 7<br>Image Loaded] --> B{Path Filter:<br>Does ImageLoaded path start with<br>C:\Windows or C:\Program Files?}
    B -- YES --> C[Ignore<br>Legitimate System Noise]
    B -- NO --> D[Anomaly Detected!<br>DLL loaded from User Directory]
    D --> E[Analyze Log Entry]
    E --> F[Look at 'Image' Field<br>👉 Hijacked Victim .exe]
    E --> G[Look at 'ImageLoaded' Field<br>👉 Attacker's Fake DLL]
    
    classDef search fill:#1e1e1e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef anomaly fill:#8b0000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef result fill:#004d00,stroke:#00ff00,stroke-width:2px,color:#fff;
    
    class A search;
    class D anomaly;
    class F,G result;
```

## 🔍 The Hunt Methodology (How to find it)

Instead of searching for an unknown name, you hunt for the behavior by using a process of elimination:

  

1. **Query Event ID 7 (Image Loaded):** This captures the exact moment any application loads a DLL into memory.
    
      
    
2. **Filter OUT the Noise:** Exclude all DLLs loading from trusted paths (`C:\Windows` and `C:\Program Files`).
    
      
    
3. **Analyze the Remnant:** You instantly reduce thousands of events down to a handful of anomalies—DLLs loading directly out of user directories.
    
      
    
4. **Identify the Victim:** Look at the `Image` field of that anomalous log. That `.exe` is the hijacked victim process, and the `ImageLoaded` field reveals the attacker's DLL.
    
      
    

> [!tip] The PowerShell Cheat Sheet
> 
> Copy and paste this directly into a PowerShell terminal to instantly filter the noise:
> 
> PowerShell
> 
> ```
> Get-WinEvent -FilterHashtable @{Path='C:\Logs\DLLHijack\*.evtx'; Id=7} | Where-Object { $_.Message -notmatch "C:\\Windows" -and $_.Message -notmatch "C:\\Program Files" } | Format-List
> ```


![Pasted image 20261022170724.png](../../Attathemnts/Pasted%20image%2020261022170724.png)









![Pasted image 20261022173627.png](../../Attathemnts/Pasted%20image%2020261022173627.png)



  

# 🛡️ Hunting Unmanaged PowerShell (The CLR Injection Method)

> [!abstract] The Core Concept (Why this works)
> 
> - **The .NET Dependency:** PowerShell relies entirely on the .NET framework to function.
>     
> - **The Injection:** Standard Windows programs (like `notepad.exe` or `svchost.exe`) are usually written in native C/C++ and have absolutely no reason to use .NET. If an attacker injects Unmanaged PowerShell into one of these normal processes, the process is suddenly forced to host the .NET environment.
>     
> - **The Indicators (`clr.dll` & `clrjit.dll`):** When the .NET environment spins up inside a process, it immediately loads the Common Language Runtime (`clr.dll`) and the Just-In-Time Compiler (`clrjit.dll`). A native process loading these DLLs is a massive red flag.
>     

## 🗺️ Visual Hunt Map

Extrait de code

```
graph TD
    A[Start: Query Sysmon Event ID 7<br>Image Loaded] --> B{Does the 'ImageLoaded' path contain<br>clr.dll or clrjit.dll?}
    B -- NO --> C[Ignore<br>Standard Activity]
    B -- YES --> D{Is the 'Image' a known .NET app<br>or powershell.exe?}
    D -- YES --> E[Ignore<br>Legitimate .NET Execution]
    D -- NO --> F[Anomaly Detected!<br>.NET Code Injection]
    F --> G[Look at 'Image' Field<br>👉 Rogue Process .exe]
    
    classDef search fill:#1e1e1e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef anomaly fill:#8b0000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef result fill:#004d00,stroke:#00ff00,stroke-width:2px,color:#fff;
    
    class A search;
    class F anomaly;
    class G result;
```

## 🔍 The Hunt Methodology

Instead of looking for PowerShell itself, we look for a process doing something it shouldn't mathematically be doing: loading a .NET compiler.

1. **Query Event ID 7 (Image Loaded):** Look at all DLL loads.
    
2. **Filter FOR the .NET Runtime:** Search exclusively for events where the DLL being loaded is `clr.dll` or `clrjit.dll`.
    
3. **Filter OUT Legitimate Hosts:** Exclude `powershell.exe` and `powershell_ise.exe`.
    
4. **Identify the Anomaly:** Look at the `Image` field. You will see a random, non-.NET executable (often a system process or a random attacker payload) acting as the host. That `.exe` is your victim process.
    

> [!tip] The XML-Bypass PowerShell Cheat Sheet Because Sysmon logs often crash the standard PowerShell text renderer, use this command to parse the raw XML. It looks for `clrjit.dll` while ignoring legitimate PowerShell executions:
> 
> PowerShell
> 
> ```
> Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" -FilterXPath "*[System[EventID=7]]" | Where-Object { $_.ToXml() -match "clrjit\.dll" -and $_.ToXml() -notmatch "powershell\.exe" } | Select-Object TimeCreated, @{Name="RawXML";Expression={$_.ToXml()}} | Format-List
> ```



![Pasted image 20261022172735.png](../../Attathemnts/Pasted%20image%2020261022172735.png)


Calculator.exe



# 🛡️ Hunting Process Injection (Finding the Injector)

> [!abstract] The Core Concept (Why this works)
> 
>   
> 
> - **The Pivot:** You cannot easily find the injector without first knowing the victim. In the previous step, you identified the victim process that was forced to run Unmanaged PowerShell (by looking for `clrjit.dll` loads). Let's call that `Victim.exe`.
>     
>       
>     
> - **How Injection is Logged:** For an attacker to force `Victim.exe` to run malicious code, the attacker's malware must reach across memory boundaries. It opens a handle to `Victim.exe`, writes the payload into its memory, and then tells `Victim.exe` to execute it.
>     
>       
>     
> - **The Indicator (Event ID 8):** Sysmon specifically logs this intrusion as **Event ID 8 (CreateRemoteThread)**. It tells you exactly who the `SourceImage` (the attacker) and the `TargetImage` (the victim) are.
>     
>       
>     

## 🗺️ Visual Hunt Map

Extrait de code

```
graph TD
    A[Start: You know the Victim Process<br>from the previous step] --> B[Query Sysmon Event ID 8<br>CreateRemoteThread]
    B --> C{Does the 'TargetImage' match<br>your known Victim Process?}
    C -- NO --> D[Ignore<br>Normal System Threading]
    C -- YES --> E[Injection Detected!]
    E --> F[Look at the 'SourceImage' Field<br>👉 This is the Injector .exe]
    
    classDef search fill:#1e1e1e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef anomaly fill:#8b0000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef result fill:#004d00,stroke:#00ff00,stroke-width:2px,color:#fff;
    
    class B search;
    class E anomaly;
    class F result;
```

## 🔍 The Hunt Methodology

The thinking process here is a "reverse timeline search." Now that you have the victim, you walk backward in the logs to see who attacked it.

  

1. **Identify the Victim:** You must already have the name of the process that executed the Unmanaged PowerShell (the answer to your previous question).
    
      
    
2. **Query Event ID 8 (CreateRemoteThread):** This event is the smoking gun for process injection.
    
      
    
3. **Filter FOR the Target:** Tell PowerShell to only show events where the `TargetImage` (the process receiving the thread) is your known victim executable.
    
      
    
4. **Identify the Injector:** Look at the `SourceImage` field in that log entry. The executable listed there is the attacker's payload that initiated the injection.
    
      
    

> [!tip] The XML-Bypass PowerShell Cheat Sheet
> 
> Replace `VICTIM_NAME.exe` with the answer you found in the previous challenge. This command searches Event ID 8 and isolates the exact process that targeted your victim:
> 
>   
> 
> PowerShell
> 
> ```
> Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" -FilterXPath "*[System[EventID=8]]" | Where-Object { $_.ToXml() -match "VICTIM_NAME\.exe" } | Select-Object TimeCreated, @{Name="RawXML";Expression={$_.ToXml()}} | Format-List
> ```
> 
> _Note: Look closely at the raw XML output. Ensure `VICTIM_NAME.exe` is in the `<Data Name="TargetImage">` field. The answer to your question will be sitting right next to it in the `<Data Name="SourceImage">` field._





![Pasted image 20261022173703.png](../../Attathemnts/Pasted%20image%2020261022173703.png)

# 🛡️ Hunting Process Injection (Finding the Injector)

> [!abstract] The Core Concept (Why this works)
> 
>   
> 
> - **The Pivot:** You cannot easily find the injector without first knowing the victim. In the previous step, you identified the victim process that was forced to run Unmanaged PowerShell (by looking for `clrjit.dll` loads). Let's call that `Victim.exe`.
>     
>       
>     
> - **How Injection is Logged:** For an attacker to force `Victim.exe` to run malicious code, the attacker's malware must reach across memory boundaries. It opens a handle to `Victim.exe`, writes the payload into its memory, and then tells `Victim.exe` to execute it.
>     
>       
>     
> - **The Indicator (Event ID 8):** Sysmon specifically logs this intrusion as **Event ID 8 (CreateRemoteThread)**. It tells you exactly who the `SourceImage` (the attacker) and the `TargetImage` (the victim) are.
>     
>       
>     

## 🗺️ Visual Hunt Map

Extrait de code

```
graph TD
    A[Start: You know the Victim Process<br>from the previous step] --> B[Query Sysmon Event ID 8<br>CreateRemoteThread]
    B --> C{Does the 'TargetImage' match<br>your known Victim Process?}
    C -- NO --> D[Ignore<br>Normal System Threading]
    C -- YES --> E[Injection Detected!]
    E --> F[Look at the 'SourceImage' Field<br>👉 This is the Injector .exe]
    
    classDef search fill:#1e1e1e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef anomaly fill:#8b0000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef result fill:#004d00,stroke:#00ff00,stroke-width:2px,color:#fff;
    
    class B search;
    class E anomaly;
    class F result;
```

## 🔍 The Hunt Methodology

The thinking process here is a "reverse timeline search." Now that you have the victim, you walk backward in the logs to see who attacked it.

  

1. **Identify the Victim:** You must already have the name of the process that executed the Unmanaged PowerShell (the answer to your previous question).
    
      
    
2. **Query Event ID 8 (CreateRemoteThread):** This event is the smoking gun for process injection.
    
      
    
3. **Filter FOR the Target:** Tell PowerShell to only show events where the `TargetImage` (the process receiving the thread) is your known victim executable.
    
      
    
4. **Identify the Injector:** Look at the `SourceImage` field in that log entry. The executable listed there is the attacker's payload that initiated the injection.
    
      
    

> [!tip] The XML-Bypass PowerShell Cheat Sheet
> 
> Replace `VICTIM_NAME.exe` with the answer you found in the previous challenge. This command searches Event ID 8 and isolates the exact process that targeted your victim:
> 
>   
> 
> PowerShell
> 
> ```
> Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" -FilterXPath "*[System[EventID=8]]" | Where-Object { $_.ToXml() -match "VICTIM_NAME\.exe" } | Select-Object TimeCreated, @{Name="RawXML";Expression={$_.ToXml()}} | Format-List
> ```
> 
> _Note: Look closely at the raw XML output. Ensure `VICTIM_NAME.exe` is in the `<Data Name="TargetImage">` field. The answer to your question will be sitting right next to it in the `<Data Name="SourceImage">` field._




![Pasted image 20261022174149.png](../../Attathemnts/Pasted%20image%2020261022174149.png)



Sysmon Event ID 8: CreateRemoteThread

- **What it means:** It logs when one process creates a thread inside a different, remote process.

- **Security significance:** Attackers commonly use **process injection** via `CreateRemoteThread` to hide malicious code, elevate privileges, or dump credentials (such as injecting into `lsass.exe`).
- 
- 
-
    - **Source Process:** (`SourceImage`, `SourceProcessId`, `SourceUser`) — the process initiating the thread.
    - **Target Process:** (`TargetImage`, `TargetProcessId`, `TargetUser`) — the process receiving the new thread.
    - **Code Details:** `StartAddress`, `StartModule`, and `StartFunction` pointing to the entry point of the injected code.





![Pasted image 20261022174647.png](../../Attathemnts/Pasted%20image%2020261022174647.png)



# 🛡️ Hunting LSASS Credential Dumping (Behavioral Approach)

> [!abstract] The Core Concept (Why this works)
> 
> - **The Target (`lsass.exe`):** The Local Security Authority Subsystem Service (LSASS) is a core Windows process that handles user authentication. Crucially, it stores active user credentials (hashes, and sometimes plaintext passwords) in its memory.
>     
> - **The Attack:** To steal those passwords, an attacker must read the memory of `lsass.exe` and save it to a file (a "dump" file). They use tools like Mimikatz, Sysinternals ProcDump, or built-in living-off-the-land binaries (like `comsvcs.dll` or Task Manager) to do this.
>     
> - **The Indicator (Sysmon Event ID 10 & 11):** Windows heavily guards LSASS. When an attacker's tool tries to read it, Sysmon logs **Event ID 10 (Process Access)**, which records one process opening a "handle" to another. If they save the memory to disk, Sysmon logs **Event ID 11 (File Create)** for the `.dmp` file.
>     

## 🗺️ Visual Hunt Map

Extrait de code

```
graph TD
    A[Start: Query Sysmon] --> B[Path 1: Event ID 11<br>File Create]
    A --> C[Path 2: Event ID 10<br>Process Access]
    
    B --> D{Does the 'TargetFilename'<br>end in .dmp?}
    D -- YES --> E[Look at 'Image' Field<br>👉 This is the Dumper .exe]
    
    C --> F{Is 'TargetImage'<br>lsass.exe?}
    F -- YES --> G{Is 'SourceImage' a normal<br>system process like svchost?}
    G -- YES --> H[Ignore<br>Normal Windows Activity]
    G -- NO --> I[Anomaly Detected!<br>Unauthorized LSASS Access]
    I --> J[Look at 'SourceImage' Field<br>👉 This is the Dumper .exe]
    
    classDef search fill:#1e1e1e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef anomaly fill:#8b0000,stroke:#ff0000,stroke-width:2px,color:#fff;
    classDef result fill:#004d00,stroke:#00ff00,stroke-width:2px,color:#fff;
    
    class A search;
    class D,F anomaly;
    class E,J result;
```

## 🔍 The Hunt Methodology

You have two distinct paths to catch an LSASS dump. In a real scenario, you check both.

### Path A: The File Drop (Event ID 11)

When an attacker dumps memory, they usually have to write it to disk as a `.dmp` file before they can steal it.

1. **Query Event ID 11 (File Create).**
    
2. **Filter FOR `.dmp`:** Look for any file created with a `.dmp` extension.
    
3. **Identify the Dumper:** If you find a `.dmp` file being created (especially in a weird folder like `\Temp\` or `\Public\`), look at the `Image` field. The process that wrote that file is your attacker.
    

### Path B: The Memory Access (Event ID 10)

If the attacker dumps the memory over the network or uses an advanced fileless technique, there won't be a `.dmp` file. You must look at the direct memory access.

1. **Query Event ID 10 (Process Access).**
    
2. **Filter FOR the Target:** Set your filter so the `TargetImage` is strictly `lsass.exe`.
    
3. **Filter OUT the Noise:** Windows system processes access LSASS constantly. Exclude normal activity where the `SourceImage` (the program doing the accessing) is `svchost.exe`, `csrss.exe`, `wininit.exe`, or your known Antivirus.
    
4. **Identify the Dumper:** Look at the remaining events. You will see a strange executable, an attacker tool, or an abused legitimate tool (like `rundll32.exe`) reaching into LSASS. That `SourceImage` is your answer.
    

> [!tip] The XML-Bypass PowerShell Cheat Sheet Run these commands to bypass the PowerShell text-rendering bug and parse the raw XML.
> 
> **To hunt via File Creation (Look for `.dmp` files):**
> 
> PowerShell
> 
> ```
> Get-WinEvent -Path "C:\Logs\Dump\*.evtx" -FilterXPath "*[System[EventID=11]]" | Where-Object { $_.ToXml() -match "\.dmp" } | Select-Object TimeCreated, @{Name="RawXML";Expression={$_.ToXml()}} | Format-List
> ```
> 
> **To hunt via Process Access (Look for rogue processes touching LSASS):**
> 
> PowerShell
> 
> ```
> Get-WinEvent -Path "C:\Logs\Dump\*.evtx" -FilterXPath "*[System[EventID=10]]" | Where-Object { $_.ToXml() -match "lsass\.exe" -and $_.ToXml() -notmatch "svchost\.exe" -and $_.ToXml() -notmatch "csrss\.exe" } | Select-Object TimeCreated, @{Name="RawXML";Expression={$_.ToXml()}} | Format-List
> ```


![Pasted image 20261022180433.png](../../Attathemnts/Pasted%20image%2020261022180433.png)



![Pasted image 20261022175438.png](../../Attathemnts/Pasted%20image%2020261022175438.png)





To trace an attacker's movement after they steal credentials, you must pivot from Sysmon logs to Windows Security logs to see where those credentials were used.

  

### 🔍 Hunting Post-Dump Lateral Movement

**1. Establish the Timeline (The Anchor)** Look at the logs in your screenshot (`image_323003.jpg`). The `lsass.exe.dmp` files were created at approximately `4/27/2022 7:00:56 PM`. This exact timestamp becomes your starting line. You do not care about any logins that happened before this moment.

  

**2. Pivot to Security Logs** When an attacker extracts passwords or hashes from the LSASS dump, they will use them to authenticate to other machines or escalate privileges. This authentication activity is recorded in the Windows `Security.evtx` log.

  

**3. Query Event ID 4624** You must query the Security log for **Event ID 4624 (Successful Logon)** occurring strictly _after_ your anchor timestamp.

  

**4. Isolate Malicious Logon Types** Windows generates hundreds of normal 4624 events in the background. To find the attacker, you must look at the `Logon Type` field within those 4624 events. You are hunting for types associated with remote access or Pass-the-Hash attacks:

  

- **Type 3 (Network):** The attacker used the stolen hash to access a network share, service, or execute remote commands (like PsExec).
    
      
    
- **Type 9 (NewCredentials):** The classic Pass-the-Hash indicator. The attacker used a tool (like Mimikatz) to inject the stolen hash into their current session using `RunAs /netonly`.
    
      
    
- **Type 10 (RemoteInteractive):** The attacker used the stolen credentials to log in graphically via RDP.
    
      
    

> [!tip] The PowerShell Cheat Sheet
> 
> You can use the `StartTime` parameter to automatically filter out all events that happened before the dump:
> 
>   
> 
> PowerShell
> 
> ```
> Get-WinEvent -FilterHashtable @{Path='C:\Logs\Dump\Security.evtx'; Id=4624; StartTime='4/27/2022 7:00:56 PM'} | Format-List
> ```

You are on the exact right track with your logic. The only minor correction is that 4624 is the **Event ID**, not a Process ID (PID). Therefore, your strategy to investigate Event ID 4624 during the period immediately following the LSASS dump is correct.



![Pasted image 20261022180904.png](../../Attathemnts/Pasted%20image%2020261022180904.png)

- **Logon Type: 5**: This designates a "Service" logon. It happens automatically when internal Windows services execute scheduled tasks or start up. It is not an interactive or remote login by a human.
    
- **Account Name: SYSTEM**: This is the built-in operating system account, not a human user whose credentials could be extracted and reused from an LSASS dump.
    
- **Process Name: C:\Windows\System32\services.exe**: This is the legitimate Windows Service Control Manager operating normally.
    

If the attacker had successfully used the credentials they stole during the LSASS dump, the event would look significantly different. You would be looking for:

- **Logon Types:** Type 3 (Network access), Type 9 (NewCredentials/Pass-the-Hash), or Type 10 (RemoteInteractive/RDP).
    
- **Account Name:** The name of a compromised user account (e.g., Administrator or a standard user).




![Pasted image 20261022181451.png](../../Attathemnts/Pasted%20image%2020261022181451.png)





# 🛡️ Hunting Strange Parent-Child Relationships (PPID Spoofing)

> [!abstract] The Core Concept (Why this works)
> 
> - **Normal Family Trees:** In Windows, programs spawn other programs in predictable ways. For example, `services.exe` spawns `svchost.exe`. `explorer.exe` (your desktop) spawns apps like `chrome.exe` when you double-click them.
>     
> - **The Attacker's Problem:** If an attacker runs a malicious script (like a macro in Word), the logs will show `winword.exe` spawning `powershell.exe`. That is a massive red flag for defenders.
>     
> - **The Evasion (PPID Spoofing & Hollowing):** To hide, an attacker will launch a legitimate, trusted Windows process (like `rundll32.exe`, `notepad.exe`, `werfault.exe`, or `dllhost.exe`), but they mathematically force it to look like it was spawned by a different parent. They then inject their malicious code into that trusted process to execute it temporarily.
>     

## 🔍 The Hunt Methodology

To find the anomaly, you must look at **Sysmon Event ID 1 (Process Create)**. This event records the exact moment a program starts, capturing both the child (`Image`) and the parent (`ParentImage`).

**1.Isolate Process Creations :**Query Event ID 1.

You need to filter your logs to exclusively show Event ID 1. This strips away all the background noise of file drops, DLL loads, and network connections.

**2.Compare Parent vs. Child :**Map the Family Tree.

Look closely at the `ParentImage` and the `Image` for each event. You are looking for a relationship that makes zero logical sense.

_Examples of Anomalies:_

- `spoolsv.exe` (The printer service) spawning `cmd.exe`.
    
- `lsass.exe` spawning a random binary.
    
- A random, unsigned executable spawning a core system file like `svchost.exe` or `werfault.exe`.
    

**3.Find the Victim Executable :**Identify the Temporary Host.

The challenge asks for the process that was used to _temporarily execute code_. This means you are looking for the **Child Process** (`Image`) in that strange relationship. The attacker spawned it just to use its memory space as a disguise.

> [!tip] The PowerShell Cheat Sheet (Relationship Mapper)
> 
> Instead of reading through long lists, use PowerShell to instantly build a table showing exactly "Who spawned Who." This command extracts the Parent and Child processes side-by-side so the anomaly sticks out immediately.
> 
> PowerShell
> 
> ```
> Get-WinEvent -FilterHashtable @{Path='C:\Logs\StrangePPID\*.evtx'; Id=1} | Select-Object TimeCreated, @{Name="Parent";Expression={($_.ToXml() | Select-Xml -XPath "//*[local-name()='Data' and @Name='ParentImage']").Node.InnerText}}, @{Name="Child (The Answer)";Expression={($_.ToXml() | Select-Xml -XPath "//*[local-name()='Data' and @Name='Image']").Node.InnerText}} | Format-Table -AutoSize
> ```





![Pasted image 20261022182101.png](../../Attathemnts/Pasted%20image%2020261022182101.png)



### 1. The Normal Relationships (Ignore these)

- **`cmd.exe` spawning `whoami.exe`:** Completely normal. A user (or script) opened a command prompt and ran the `whoami` command to check their privileges.
    
- **`cmd.exe` spawning `conhost.exe`:** Completely normal. `conhost.exe` (Console Window Host) is a required Windows process that physically draws the black terminal window on your screen whenever `cmd.exe` opens.
    
- **`explorer.exe` spawning `WerFault.exe`:** Mostly normal. `explorer.exe` is your Windows desktop. `WerFault.exe` is the **Windows Error Reporting** tool. If an application crashes on your desktop, Windows automatically launches `WerFault.exe` to collect a crash dump and send it to Microsoft.
    

### 2. The Strange Relationship (The Anomaly)

- **`WerFault.exe` spawning `cmd.exe`**: **This is a massive red flag.**






