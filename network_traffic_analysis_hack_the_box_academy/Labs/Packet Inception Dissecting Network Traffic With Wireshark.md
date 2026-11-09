

![Pasted image 20261109104913.png](../../Attathemnts/Pasted%20image%2020261109104913.png)


- **Open your PCAP file** in Wireshark.
    
- Go to the top menu and click **File > Export Objects > HTTP...**.[](https://ask.wireshark.org/question/29732/filter-to-find-the-particular-jpg-in-the-pcap/?answer=29736#post-id-29736)[](https://openeuler.csdn.net/6a393ff210ee7a33f280d788.html)
    
- A new window will pop up listing all the files Wireshark found in the HTTP traffic. Look for entries where the **Content Type** is an image format, like `image/jpeg` or `image/png`.[](https://openeuler.csdn.net/6a393ff210ee7a33f280d788.html)
    
- You can also sort by **Filename** to see the actual names of the files being transferred. This is often the most direct clue.[](https://www.positioniseverything.net/how-to-get-images-from-wireshark/#1)
    
- Select a likely image file and click **Save** to export it to your computer.


![Pasted image 20261109104946.png](../../Attathemnts/Pasted%20image%2020261109104946.png)![Pasted image 20261109105017.png](../../Attathemnts/Pasted%20image%2020261109105017.png)







