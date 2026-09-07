# Final Project Proposal

## Group Members:

Steven Breger, Rahul Deb
       
# Intentions:

We are building a terminal-based encrypted messaging application that connects multiple clients to a central server. The goal is to implement real cryptographic protocols from scratch rather than using libraries.
 
The three proposals we considered were a Secure Messenger, an MD5 Password Database Checker, and an MD5 Collision Finder. We chose the Secure Messenger because it gave us the most opportunity to combine multiple algorithms (RSA, Diffie-Hellman, AES, and string searching).
    
# Intended usage:

A server is started first and listens for incoming connections. Clients connect to it through the terminal. On connection, the client and server automatically perform identity verification using RSA and then run a Diffie-Hellman key exchange to establish a shared session key. After that, the user can type messages which are encrypted with AES before being sent, and decrypted on the receiving end.
 
Clients can also search through the message log using a built-in search tool that uses Boyer-Moore (single pattern) or Aho-Corasick (multiple patterns), and can request a list of currently connected clients.
  
# Technical Details:

**Cryptography:**
- Miller-Rabin primality test to generate large primes for RSA
- RSA public/private key pairs for identity verification between client and server
- Diffie-Hellman key exchange using a safe prime to establish a shared session key
- AES-128 in CTR mode to encrypt all messages, with the session key derived by hashing the Diffie-Hellman output with SHA-256

**String Searching:**
- Boyer-Moore algorithm for single-pattern search through the message log
- Aho-Corasick algorithm for multi-pattern search

**Networking:**
- Python socket library for the client-server connection
Steven was primarily responsible for the RSA, Miller-Rabin, and Diffie-Hellman implementations as well as the overall client-server networking stuff. Rahul was primarily responsible for the AES implementation and the string searching algorithms.
    
# Intended pacing:

**Week 1:** Set up the socket connection between client and server. Implement Miller-Rabin and RSA.
 
**Week 2:** Implement Diffie-Hellman key exchange. Begin AES implementation.
