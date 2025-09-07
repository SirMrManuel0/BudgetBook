
# NOT UPTODATE (will be changed .... sometime)

for devs:

to easier do PyTest use following command (ensure Docker is installed and running):

Windows Powershell

```commandline
docker build -f DockerfilePytest -t budgetbook_pytest . ; docker run --rm -it budgetbook_pytest ; docker rmi budgetbook_pytest
```

should work on Windows Powershell... probably.

# BudgetBook
1. [How to use](#1-how-to-use)
   1. [Server](#i-server)
   2. [Local](#ii-local)
2. [Features](#2-features)
3. [Security](#3-security)
4. [Errors](#4-errors)
5. [Contributions](#5-contributions)
6. [License](#6-license)


## 1. How to use

There are two ways to utilise this project.

The preferred (by me) is to use it as a server in a local network; it can be enjoyed on every device and is more convenient.

The other method is to use it locally on a device. This way it is less flexible.

However, even if you set it up as a server, you can still use the local variant as they access the same database and protocols (except for the handshake, connection protocols, etc.).

To use it install the latest release. There should be a server.exe and local.exe.

### i. Server

On Windows:

1. Install the latest release
2. execute the server.exe or:

Unpack the source code and execute:
```
python main.py --mode server --ip 127.0.0.1 --port 8080
```

The default ip is 127.0.0.1 (localhost).

The default port is 8080.

### ii. Local

On Windows:

1. Install the latest release
2. execute the client.exe or:

Unpack the source code and execute:
```
python main.py --mode local
```

## 2. Features

1. Backups
2. Analytics

## 3. Security

1. RSA
2. AES-GCM
3. ChaCha20-Poly1305

## 4. Errors

## 5. Contributions

1. SirMrManuel0
2. FishAndChips231

## 6. License

[MIT-License](LICENSE.md)
