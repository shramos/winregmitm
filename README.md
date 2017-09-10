# Description
Winregmitm is a tool that performs filtering, processing and forwarding of packets from the Windows Remote Registry protocol. To perform these actions, the tool must be placed in the middle of the communication between a client and a server that are exchanging information through this protocol. The tool will be able to capture the packets and modify them depending on the type of packet or the information to be entered, in such a way that allows the insertion of random data in the victim's Windows registry and consequently, the execution of commands remotely. To perform this process, the tool interprets all the raw bytes of the packets, including the layers: IP / TCP / NetBIOS / SMB2 / DCE-RPC / WINREG. In addition to this, it implements a correction mechanism for the sequence numbers of a TCP / IP session, so that, even if a packet size is increased or decreased in the middle of the communication between the client and the server, the connection is still active.
In addition, there are situations in which the Windows Remote Registry Protocol encrypts the payload of the WINREG layer, which prevents this attack. To solve this, the tool implements a mechanism that allows to force the authentication of a session that is supposed to be encrypted, so that it goes unencrypted. To force the authentication, the tool implements some mechanisms for breaking a session in progress.
Winregmitm is the first public tool capable of modifying the packets that come from the Windows Remote Registry Protocol, modify the values that are being put in the remote registry of the victim, modify the name of the keys that are being opened or modify the path and the name of the new keys being created.

# Installation
First of all, we need to install netfilterQueue, for doing that, on Debian or Ubuntu, run the next command:

```apt-get install build-essential python-dev libnetfilter-queue-dev```

After that, we need to install all python requirements:

```pip install -r requirements.txt```

That's all! You are ready to rock!

# Examples

## Without parameters

With the command:

```python winregmitm.py```

the tool will enter in monitoring mode, it will record all the client movements in the server Windows Registry. It may be useful to select when to insert a particular value or extract the name of a key to use with the option ```--key```.

## SetValue operation

The ```--value``` or ```-val``` option is used to intercept all **setvalue** packets that flow from the client to the server, these types of packages are used to establish a value in a certain key of the windows registry of the remote machine. The use of this option is very simple:

```python winregmitm.py --value attackervalue```

This statement will replace the original value that the **setvalue** packet contains by the value *attackervalue*.

## OpenKey operation

The ```--key``` or ```-k``` option is used to intercept all **openkey** packets that flow from the client to the server, these type of packets are used to open a certain key of the windows registry of the remote machine. It is used as follows:

```python winregmitm.py --key "S-1-5-21-3397293157-906935177-3907816343-1000\Keyboard Layout"```

This statement will replace the original key that the **openkey** packet contains by the key *S-1-5-21-3397293157-906935177-3907816343-1000\Keyboard Layout*. In such a way that when the user thinks that he is opening a certain key, he is opening the key provided by the attacker.

You can also combine both options as follows:

```python winregmitm.py --key "S-1-5-21-3397293157-906935177-3907816343-1000\Keyboard Layout" --value "attackervalue"```

## CreateKey operation

The ```--newkey``` or ```-nk``` option is used to intercept all **CreateKey** packets that flow from the client to the server, these type of packets are used to change the name a certain key that is been created on the windows registry of the remote machine. It is used as follows:

```python winregmitm.py --newkey "newattackername"```

You can also force the key to be created in another path of the remote machine's registry by using the following command:

```python winregmitm.py --newkeypath "S-1-5-21-3397293157-906935177-3907816343-1000\Keyboard Layout" --newkey "newattackername"```

## Forcing a session that is supposed to be encrypted to go unencrypted

If the user of the client and the server machines that communicate via the Windows Remote Registry Protocol have the same user and password, the authentication will be performed automatically, and in addition, the payload of the *winreg* packages will be encrypted. To prevent this from happening, we can force the authentication of a session that is supposed to be encrypted to go unencrypting. To do this, we use the following command:

```python winregmitm.py --encrypted```

This command will force at the time of authentication that the session goes unencrypted. If the session has already started, we can use this option in combination with ```--break-connection``` or  ```-bk```, to break the current connection and force the user to re-authenticate.

```python winregmitm.py --break-connection --encrypted```

This will break the currently established connection between the client and the server and the next time it is authenticated, it will force it to go unencrypted.

# Video Examples

###### Setting a test enviroment for winregMITM tool in Windows 10
https://www.youtube.com/watch?v=fzkeEJG7l4Q

###### Breaking and forcing a Windows Remote Registry Protocol session to go unencrypted in Windows 10
https://www.youtube.com/watch?v=gZ37Pkp9ic4

# Contact
shramos@protonmail.com
