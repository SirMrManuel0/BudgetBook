# File Types

Within the BudgetBook there are different file types to store user and system data. These file types are:

Unless otherwise defined encryption is done with the XChaCha20-Poly1305 algorithm.

- .hb
- [.et](#et)
  - [File Structure](#et-file-structure)
- [.ej](#ej)
  - [File Structure](#ej-file-structure)
- [.k_hb](#khb)
  - [Table Structure](#khb-table-structure)
  - [File Structure](#khb-file-structure)
- [.epng](#epng)
  - [File Structure](#epng-file-structure)
- (.template to show how a file is structured)
***
## .hb
***
## .et
***

An ET file is an encrypted CSV file. The difference to a normal CSV is the structure after encryption.

<h3 id="et-file-structure">File Structure</h3>

| Offset    | Field               | Size (bytes) | Description                      |
|-----------|---------------------|--------------|----------------------------------|
| 0         | ID length       | 5            | Number of bytes in ID field      |
| 5         | ID              | m            | ID in bytes                      |
| 5 + m     | Version length  | 3            | Number of bytes in version field |
| 5 + 3 + m | Version         | n            | Version string in bytes          |
| 8 + m + n | Encrypted JSON | ... | The encrypted CSV data           | 


## .ej
***
An EJ file is an encrypted JSON file. The difference to a normal JSON is the structure after encryption.

<h3 id="ej-file-structure">File Structure</h3>

| Offset    | Field               | Size (bytes) | Description              |
|-----------|---------------------|--------------|--------------------------|
| 0         | ID length       | 5            | Number of bytes in ID field |
| 5         | ID              | m            | ID in bytes |
| 5 + m     | Version length  | 3            | Number of bytes in version field |
| 5 + 3 + m | Version         | n            | Version string in bytes |
| 8 + m + n | Encrypted JSON | ... |The encrypted JSON data | 

## .khb
***
A KHB file is a key file which stores all file keys. Every user has one and there is one for the system.
It is an encrypted CSV file.

<h3 id="khb-table-structure">Table Structure</h3>

| file id | file_key (encrypted) | salt | nonce | hash |
|---------|----------------------|------|-------|------|
| base64 | base64 | base64 | base64 | base64 |

The **file id** is simply an uInt.

The **file key** is encrypted with a key which is derived from the salt and the key needed
to unlock the file. The purpose is to ensure the file key is not stored in clear text even in memory. (Yes, if the
key to unlok the file is also stored in memory, this is obfuscation and, thus, does not exactly provide a great deal
of security.) 

The **nonce** is simply the nonce which was used to encrypt the file.

The **hash** is of the file to which the key is assigned to
(which is why I don't think a signature in the file itself is necessary).

<h3 id="khb-file-structure">File Structure</h3>

The file itself is then encrypted and has after encryption the following format:

| Offset           | Field               | Size (bytes) | Description              |
|------------------|---------------------|--------------|--------------------------|
| 0                | Version length      | 3 | Number of bytes in version |
| 3                | Version             | n | Version string in bytes  |
| 3 + n            | Nonce               | 24 | Nonce for the encryption |
| 3 + n + 24       | Encrypted key file  | m | The encrypted key file |
| 3 + n + 24 + m | Signature (Ed25519) | 64 | The key file is signed with the system private key |


## .epng
***
An EPNG file is just a PNG file which was encrypted. Its file name (file_name.epng) is the file id, which is necessary to
find the correct key and hash in the key file. The beginning bytes (currently 5) define how many bytes after it are the
file id. That way even if the file name was changed by the user, the file can still be found. After the file id follow
3 bytes which define the length of the version. Followed by the version bytes.

<h3 id="epng-file-structure">File Structure</h3>

| Offset        | Field           | Size (bytes) | Description |
|---------------|-----------------|--------------|--------------|
| 0             | ID length       | 5            | Number of bytes in ID field |
| 5             | ID              | m            | ID in bytes |
| 5 + m         | Version length  | 3            | Number of bytes in version field |
| 5 + 3 + m     | Version         | n            | Version string in bytes |
| 5 + 3 + m + n | Encrypted image | variable     | Binary image data (encrypted) |