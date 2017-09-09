# Description
Winregmitm is a tool that performs filtering, processing and forwarding of packets from the Windows Remote Registry protocol. To perform these actions, the tool must be placed in the middle of the communication between a client and a server that are exchanging information through this protocol. The tool will be able to capture the packets and modify them depending on the type of packet or the information to be entered, in such a way that allows the insertion of random data in the victim's Windows registry and consequently, the execution of commands remotely. To perform this process, the tool interprets all the raw bytes of the packets, including the layers: IP / TCP / NetBIOS / SMB2 / DCE-RPC / WINREG. In addition to this, it implements a correction mechanism for the sequence numbers of a TCP / IP session, so that, even if a packet size is increased or decreased in the middle of the communication between the client and the server, the connection is still active.
In addition, there are situations in which the Windows Remote Registry Protocol encrypts the payload of the WINREG layer, which prevents this attack. To solve this, the tool implements a mechanism that allows to force the authentication of a session that is supposed to be encrypted, so that it goes unencrypted. To force the authentication, the tool implements some mechanisms for breaking a session in progress.
Winregmitm is the first public tool capable of modifying the packets that come from the Windows Remote Registry Protocol, modify the values that are being put in the remote registry of the victim, modify the name of the keys that are being opened or modify the path and the name of the new keys being created.

# Installation
First of all, we need to install netfilterQueue, for doing that, on Debian or Ubuntu, run the next command:

```apt-get install build-essential python-dev libnetfilter-queue-dev```

After that, we need to install all python requirements:

```pip install -r requirements.txt```



# Examples
