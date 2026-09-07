# Dev Log:

This document must be updated daily every time you finish a work session.

## Rahul Deb

### 2026-05-11 - Started work on Boyer Moore string search algorithm
- Started researching and implementing the bad character heuristic for Boyer-Moore algorithm by generating and doing fast lookup with a preprocessed table

### 2026-05-12 - Continued work on good suffix for Boyer Moore algorithm
- Added a good suffix shift table function to check which suffix in end of pattern match to a prior sub-pattern

### 2026-05-13 - finished implementing boyer moore algorithm
- implementing checking for maximum shift between bad character and good suffix to finish naive boyer moore

### 2026-05-14 - started working on aho corasick algorithm
- impelemented basic structure of trie and finished failure links checking function with BFS

### 2026-05-15 - finished implementing string algorithms
- finished working on aho corasick + tested it
- put boyer moore and aho corasick calls together in main.py

### 2026-05-(16-18) - set up docker on digital ocean
- set up docker on the docker-setup branch and added it to the digitalocean droplet but decided not to use it and just manually start the server

### 2026-05-(19-20) - started researching on aes
- started researching & learning how aes encryption works

### 2026-05-21 - finished implementing aes encryption
- implemented the aes encryption using sub, shift, mix (using polynomial multiplication from the galois field), and xoring with the round keys

### 2024-05-22 - refactored code and removed client to client messaging
- Refactored project structure into a shared directory
- cleaned up unused imports and types
- removed client-to-client sending while keeping client send locks to make sure there's no concurrent socket write corruption.

### 2026-05-23 - finished implementing ctr & testing aes handler
- implemented ctr to turn aes from block to stream cipher
- finished testing & fixing all the bugs for aes handler

### 2026-05-24 - added aes to the stream handler and finished merging
- added the ctr stream cipher to the stream_handler
- moved aes_handler to the shared folder & merged with main
- fixed import issues with the shared folder

### 2026-05-(25-26) - added search function and finished project
- added search handler to search for substrings using boyer moore/aho-corasick
- finished working on presentation.md and the video