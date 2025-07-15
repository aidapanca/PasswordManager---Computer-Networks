# PasswordManager---Computer-Networks
Computer Networks: Multithreaded TCP Password Manager in C with SQLite backend (Linux)

# Password Manager (C)

A client/server password manager written in C that uses TCP/IP for communication, **pthread** for concurrency and SQLite 3 for secure data persistence.  
Multiple users can register, organise their passwords by category and safely recover their account through security questions. :contentReference[oaicite:0]{index=0}

## Overview

The server listens on **port 2500**, accepts TCP connections and spawns a dedicated **thread** for each client.  
The client provides a minimal CLI where users send textual commands and receive formatted replies. 

---

## Features

- **Registration & Login** (`REGISTER`, `LOGIN`)
- **Password‑strength validation** (≥ 8 chars, mixed case, digits, special symbols)
- **Security question & answer** for recovery (`REGISTER_SEC`, `SEC_QUESTION`, `RECOVER_PASS`)
- **Category management**: create / list / delete (`NEW_CAT`, `LIST_CATS`, `DEL_CAT`)
- **Entry management**: add / modify / list / delete passwords (`NEW_ENTRY`, `MOD_ENTRY`, `LIST_ENTRIES`, `DEL_ENTRY`)
- **Master‑password change** (`CHANGE_PASS`)
- **Concurrent connections** via _pthread_
- **SQLite persistence** with foreign keys & uniqueness constraints
- **Text‑based protocol** decoupled from business logic, easy to extend

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| **C99**    | main language (server & client) |
| **POSIX Sockets** | TCP/IP communication |
| **pthread**| multithreading on the server |
| **SQLite 3** | embedded relational storage |
| **GNU/Linux** | recommended build/runtime environment |

---

## Architecture

1. **Client**  
   - Opens a socket, connects to the server (`connect`) and sends commands with `write`.  
   - Prints responses read via `read`. :contentReference[oaicite:2]{index=2}  

2. **Server**  
   - Listens on a socket, accepts clients and launches one _thread_ (`pthread_create`) per connection.  
   - Parses commands, executes DB operations and returns results. :contentReference[oaicite:3]{index=3}  

3. **SQLite DB**  
   - Tables **Users**, **Categories**, **Entries** with User ↔ Category ↔ Entry relations and unique constraints on titles. :contentReference[oaicite:4]{index=4}  

---

