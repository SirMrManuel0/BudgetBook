# BudgetBook
1. How to use
   1. Server
   2. Local
2. Features
3. Security
4. Errors
5. Contributions


## 1. How to use

There are two ways to utilise this project.

The preferred (by me) is to use it as a server in a local network; it can be enjoyed on every device and is more convenient.

The other method is to use it locally on a device. This way it is less flexible.

However, even if you set it up as a server, you can still use the local variant as they access the same database and protocols (except for the handshake, connection protocols, etc.).

To use it install the latest release. There should be a server.exe and local.exe.

### i. Server

1. Install the latest release
2. execute the server.exe or:

Unpack the source code and execute:
```
python main.py server
```

### ii. Client

1. Install the latest release
2. execute the client.exe or:

Unpack the source code and execute:
```
python main.py client
```