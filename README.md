## Project Overview
Designed an online secure file system written in Golang where users can create accounts as well as create, share,
and revoke files with other users like DropBox. Encrypted all user data using public key encryption and symmetric
encryption schemes to uphold confidentiality, integrity, and authenticity on the data server.

## Background on project
This project implements secure file sharing in the given threat model that deals with two diffrent types of adversaries, datastore adversary and revoked user adversary, while still maintianing efficient read, write, shares and appends.

### Threat Model
#### Datastore adversary 
The Datastore is an untrusted service hosted on a server and network controlled by an adversary. The adversary can view and record the content and metadata of all requests (set/get/delete) to the Datastore API. This allows the adversary to know who stored which key-value entry, when, and what the contents are.

An adversary can add new key-value entries or modify any current key-value entries in the datastore at any time. However, given a snapshot of the datastore at some time, t, an adversary cannot fully revert the datastore to it’s state at time t-1. Similarly, an attacker cannot rollback a file to a previously seen state on the datastore.

#### Revoked user adversary
A user who is granted access to a file is considered trusted and will only use the system through the Client API functions. However, after a user has their access to a shared file revoked, that user may become malicious, ignore your client implementation, and use the Datastore API directly.

Malicious users may try to perform operations on arbitrary files by utilizing the request/response information that they recorded before their access was revoked. All writes to Datastore made by a user in an attempt to modify file content or re-acquire access to file are malicious actions.

### Prerequisite To Run this Project
- Install Golang v1.17 or newer.

### Commands To Run this Project
- In the client_test directory of the checked out repository, run `go test`. 


