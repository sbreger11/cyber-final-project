[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/B2vtqcJe)
# Encrypted Messaging Application
 
### The Defenders of the Internet
Steven Breger
Rahul Deb

---
       
### Project Description:

This is an encrypted messaging application that connects clients to a server and then allows the clients to send messages to other clients. The system works with the trust on first use model and verifies identities each time using RSA. It then performs the diffie-hellman key exchange in order to exchange a shared secret key. Finally, it encrypts every message sent with AES.

---
 
### Video Presentation
 
[Google Drive](https://drive.google.com/file/d/1L8j34aNKS_R--Wbvd_GrfE00en6YOTG5/view?usp=sharing) | [YouTube](https://www.youtube.com/watch?v=jUqmFXt2-rY) | [PRESENTATION.md](./PRESENTATION.md)


---
  
### Instructions:

> **NOTE:** all the following commands can only be run from the root directory of the repo

> **NOTE:** if you are using a local server to connect clients to, it is advised to start the server before the clients

For this program to work. You need to connect clients to a server. There is a client and there is an alt_client. These are duplicate versions of the same program so that it is possible to test broadcasting a message from one client to another.

A droplet server is setup with our program running so you can run the following two commands (in different terminals) to connect clients to it:
```
make client_connect_droplet
make alt_client_connect_droplet
```

If you would like to make your own local facing only or public facing server you can type one of the following:
```
make local_server
make public_server
```

To connect a client to any server running on your machine, you may the following (in different terminals):
```
make client_connect_local
make alt_client_connect_local
```

**Usage instructions:**

- **For servers:** once a server is started it will keep running until manually shut down with a keyboard interrupt. There are no other controls needed.

- **For clients:** once you connect to a server you may type the "help" command inside the program and instructioons will appear.


### Resources/ References:

**Background Reading:**
- Original searching for algorithms: https://www.mdpi.com/1999-4893/18/11/709

**Boyer-Moore Algorithm:**
- Boyer-Moore algorithm notes: https://www.cs.ucdavis.edu/~gusfield/cs224f11/bnotes.pdf

**Aho-Corasick Algorithm:**
- Aho-Corasick algorithm slides: https://web.stanford.edu/class/archive/cs/cs166/cs166.1186/lectures/02/Small02.pdf

**AES (Advanced Encryption Standard):**
- AES overview: https://www.geeksforgeeks.org/computer-networks/advanced-encryption-standard-aes/
- AES video explanation: https://www.youtube.com/watch?v=O4xNJsjtN6E
- AES official specification: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf

**Socket**
- https://realpython.com/python-sockets/

**Miller-Rabin**
- https://crypto.stanford.edu/pbc/notes/numbertheory/millerrabin.html
- 
**RSA**
- https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/  
