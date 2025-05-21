dns2tcp
=======

A DNS tcp proxy with some capture for practice.

## Usage

This tool acts as a UDP DNS proxy that forwards DNS queries received on UDP port 53 to a designated DNS server over TCP (currently hardcoded to Google's `8.8.8.8:53`).

To run the application:
```bash
# Requires privileges to bind to port 53, often sudo is needed.
sudo ./dns2tcp
```

To test if it's working, you can point a DNS client like `dig` or `nslookup` to `127.0.0.1`:
```bash
dig @127.0.0.1 yourdomain.com
```

## Development/Setup Steps

This project is written in Go.

### Prerequisites
- Go (version 1.16 or later recommended).

### Building from Source
1. Clone the repository (if you haven't already).
2. Navigate to the project directory.
3. To build the executable:
   ```bash
   go build dns2tcp.go
   ```
   This will create an executable named `dns2tcp` (or `dns2tcp.exe` on Windows) in the current directory.

### Running Tests
Unit tests are provided to verify functionality, especially the DNS message parsing.
1. Ensure Go modules are initialized (this should have been done if tests were run previously):
   ```bash
   go mod init dns2tcp 
   # (Or your chosen module name if different)
   ```
2. To run the tests:
   ```bash
   go test -v
   ```

TODO
----

1. DNSCrypt support.
