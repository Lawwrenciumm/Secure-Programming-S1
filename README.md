# Secure Communication Application for group 28

**Python source code for Advanced Secure Protocol Design, Implementation and Review.**

University of Adelaide | Secure Programming 3307 

**Group Members:**

Harrison Lan (a1798025)

Lawrence Smythe (a1827540)

Isaac Joynes (a1827396)


> [!IMPORTANT]
> Error free code files are client.py and server.py
> And Vulnerable files are vulnerableClient.py and vulnerableServer.py

# Usage
The code is written with python, install python through your preferred source if needed.

Too lazy? Just download from [Python.org](https://www.python.org/).

> [!IMPORTANT]
> Websockets and Cryptography are required libraries. No, it is not negotiable.

Install the required libraries using the following command: <br />

``` pip install websockets cryptography ```

Once finished, proceed to run server and client files.

## server.py

Run the server by simpliy typing

```python server.py``` 

When prompted with ```Enter Preset Number or manual: ```, you can either enter a preset number or if you are feeling adventurous today, type ```manual``` for a custom setup. 

> [!TIP]
> For express testing, recommend using ```1``` for the first server, ```2``` for the second server.

For custom setup, three options will be prompted, ```Server IP```, ```Server Port```, ```Server ID``` and ```Server Connections```, enter info accordingly.<br /><br />
Server uri format is as following ```ws://<ip-address>:<port-number>```. For exmaple, the testing preset 1 is hosted at ```ws://localhost:23451```, preset 2 is hosted at ```ws://localhost:23452```.<br /><br />
```Server ID``` option require every server to have its own, unquie ID. Preset 1 uses the id of ```1```, preset 2 uses the id of ```2```.<br /><br />
```Server Connections``` requires input of other servers with a direct connection, according to the [OLAF/Neighbourhood protocol](https://github.com/xvk-64/2024-secure-programming-protocol). 

## client.py

Run the client file by using

```python client.py``` 

When prompted with ```Enter Preset Number or manual: ```, you can either enter a preset number or type ```manual``` for a custom setup. 

> [!TIP]
> Just like the server, for express testing, recommend using ```1``` to connect to server using preset 1, ```2``` to connect server using preset 2.

To connect to custom uri, it should be the same uri as your server setup, in the format of ```ws://<ip-address>:<port-number>```. But while entering in terminal, you can omit ```ws://``` from your input.

Once chosen your setup, you will be prompted ```Enter your name: ```, just enter name you can remember, or your least favorite Itlian brand dog food. Leave it empty, and you shall be named ```Anonymous```.

If you didn't mess anything up, your client will be connected to the server by now. ```COMMANDS``` should appear in your terminal, most of them are self explanatory.

Start typing now to send message into public chat.

> [!WARNING]
> Everyone on the same and neighbouring server will see it!

To send a private message, use the command ```/clients``` to find another user that you want to harass, copy the string after ```ID: ```. Then use ```/msg <string-you-just-copied> <message>``` to send a private message.

To upload a file to the server, use the command ```/upload <path/to/file.txt>``` and when you would like to download that file off the server, use the command ```/download <file_name>```.

