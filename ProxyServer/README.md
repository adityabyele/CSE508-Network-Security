### Proxy Server
---
* Avoids direct exposure of the clients to the server, preventing unauthenticated exploitation of a known vulnerability in server(e.g remote code execution before the authentication process is complete).
* Runs on both the client side and the server side
* The client side application reads plain text from std in and encrypts it using AES in CTR mode with a static key sent to it on first connection and sends this encrypted data to the proxy server.
* The proxy server , listening for connection decrypts the data it receives and forwards it to the server.
* Thus any unauthorized data is garbage to the server.

#### Usage
./pbproxy&nbsp;[-l &nbsp;port] &nbsp;-k &nbsp;keyfile &nbsp;destination &nbsp;port 

-l&nbsp;&nbsp;&nbsp;Reverse-proxy mode: listen for inbound connections on <port> and relay them to <destination>:<port>

-k&nbsp;&nbsp;&nbsp;Use the symmetric key contained in <keyfile> (as a hexadecimal string)

***
#### References:

* http://www.binarytides.com/socket-programming-c-linux-tutorial/
* https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
* https://stackoverflow.com/questions/38255433/parameter-details-of-openssls-aes-ctr128-encrypt
* https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
