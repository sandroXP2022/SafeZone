# SafeZone 0.0.1

SafeZone is an encrypted credential manager in TUI (ncurses) that uses AES-256 and SHA-512 for security.

## Features
- **Lightweight code (only 300 lines of code)**
- **TUI interface for managing credentials and other encrypted data**
- **AES-256 encryption for file encryption**
- **Integrity check system (using SHA-512 hash verification)

## Dependencies

* `g++`
* `make`
* `ncurses` and `ncurses-devel`
* `openssl` and `libssl-dev`


## Installation
The program can be compiled and installed on the system in a simple way using:
```bash
make && sudo make install
```
The binary will be moved to `/usr/bin/safezone`, now you need to edit the configuration file `/root/.config/safezone/config` to add the partition that will be used to store the keys.

> You need to have a free partition (I recommend using external storage for a more secure experience).

The configuration file must have the variable DRIVE for the program to use that partition to store the keys.
```
DRIVE=/dev/sda1
```

## Execution
To start the program, run ``sudo safezone``.

Translated with DeepL.com (free version)
