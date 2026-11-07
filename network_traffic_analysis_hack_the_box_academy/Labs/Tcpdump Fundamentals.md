

![Pasted image 20261106172026.png](../../Attathemnts/Pasted%20image%2020261106172026.png)

To be honest this one is obvious 
on the first request we can see that the locally address is trying to set up the hello message with the server so that's it :

![Pasted image 20261106172110.png](../../Attathemnts/Pasted%20image%2020261106172110.png)



![Pasted image 20261106172504.png](../../Attathemnts/Pasted%20image%2020261106172504.png)


We know it is **relative** because of how ==packet analysis tools like **Wireshark** display sequence numbers by default== to make analysis easier for humans.

Here is exactly how it works:

- **What actually happens:** When two devices start talking, they pick a completely random 32-bit number as their starting sequence number (e.g., `2,843,921,405`). This is the **absolute sequence number**.
- **What Wireshark does:** Tracking numbers in the billions during a packet capture is incredibly difficult. To simplify this, Wireshark automatically subtracts that massive random starting number and displays the very first packet as **`0`**.
- **The giveaway:** If you look at the raw bytes of the packet (the hex stream at the bottom), you will see the true, massive absolute number. But in the packet details pane and the info column, Wireshark translates it to **`0, 1, 2, 3...`** so you can easily track how many bytes of data have been sent.


![Pasted image 20261107130212.png](../../Attathemnts/Pasted%20image%2020261107130212.png)


By using :

![Pasted image 20261107130239.png](../../Attathemnts/Pasted%20image%2020261107130239.png)




![Pasted image 20261107130847.png](../../Attathemnts/Pasted%20image%2020261107130847.png)

Pay attention to ==🔴### (Please use best practices when using switches)==

It was a hint of the previous question 

![Pasted image 20261107131334.png](../../Attathemnts/Pasted%20image%2020261107131334.png)

```
sudo tcpdump -Xr /tmp/capture.pcap
```

![Pasted image 20261107131429.png](../../Attathemnts/Pasted%20image%2020261107131429.png)


![Pasted image 20261107131720.png](../../Attathemnts/Pasted%20image%2020261107131720.png)



![Pasted image 20261107131800.png](../../Attathemnts/Pasted%20image%2020261107131800.png)


