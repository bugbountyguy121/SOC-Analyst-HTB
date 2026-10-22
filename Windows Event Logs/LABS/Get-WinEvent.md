
## Practical Exercise

Navigate to the bottom of this section and click on `Click here to spawn the target system!`

Then, RDP to `[Target IP]` using the provided credentials and answer the question below.

  ### Utilize the Get-WinEvent cmdlet to traverse all event logs located within the "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement" directory and determine when the \\*\PRINT share was added. Enter the time of the identified event in the format HH:MM:SS as your answer.




So this is the first peace of the puzzle 
### The Point of It

In a security investigation, when you suspect an attacker or malware created a shared folder on a network computer to dump files or move laterally, this command searches the Windows Security Event logs for **Event ID 5142**—which is the exact event Windows generates when a network share object is added (such as a share named `\\[Server]\PRINT`).



Amazing Now lets move on 


We have the source of the logs located on 

"C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement"


By taking this part of the notes + the little research we did on the \\share  we can actually solve this 

From :
```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```


To :

```

PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement\net_share_drive_5142'; ID=5142} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

![[../../Attathemnts/Screenshot_2026-10-22_12-53-56.png|Screenshot_2026-10-22_12-53-56.png]]



![[../../Attathemnts/Pasted image 20261022140403.png|Pasted image 20261022140403.png]]



