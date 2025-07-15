# PasswordManager - Computer-Networks
Computer Networks: Multithreaded TCP Password Manager in C with SQLite backend (Linux)

# 🔐 Password Manager – Secure Credential Storage over TCP

A multithreaded client/server password manager written in C, offering secure and structured storage for user credentials. The system provides category-based organization, authentication with master passwords, recovery via security questions, and real-time interaction via TCP/IP sockets.


## Tech Stack

- *Language*: C
- *Platform*: Linux / UNIX
- *Concurrency*: POSIX threads (`pthread`)
- *Networking*: TCP/IP (using socket, bind, listen, accept, connect)
- *Database*: SQLite3
- *Communication*: Plain-text protocol over TCP


## Core Features

-  *User Account Management*
  - REGISTER: Create new accounts
  - LOGIN: Authenticate using a master password
  - CHANGE PASS: Change current password

-  *Password Storage*
  - Organized by user-defined categories
  - Each entry includes: title, username, password, URL, notes
  - Commands: NEW CAT, LIST CAT, DEL CAT, NEW ENTRY, MOD ENTRY, DEL ENTRY

-  *Password Recovery*
  - REGISTER SEC: Set security question & answer
  - SEC QUESTION: Retrieve security question
  - RECOVER PASS: Recover master password after verification

-  *Multithreaded Server*
  - Each client is handled in a separate thread for concurrent access



## 🧠 Architecture

The application follows a *modular client-server architecture* with the following design principles:

- *TCP-based communication* – Stable and ordered message exchange between client and server using plain-text commands.
- *Multithreaded server* – Each client connection is handled independently using POSIX threads, ensuring scalability and responsiveness.
- *Normalized SQLite schema* – Used for persistent and secure data storage, including users, categories, and password entries.
- *Command dispatcher pattern* – Input parsing is centralized, enabling simple extension and consistent request handling.
- *Recovery-first design* – Account security is enhanced with a fallback mechanism using security questions.

