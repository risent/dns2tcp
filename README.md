dns2tcp
=======

A DNS proxy that forwards local UDP DNS queries to a DNSCrypt v2 resolver.

## Usage

This tool acts as a local DNS proxy, receiving standard DNS queries on UDP port 53 and forwarding them securely to a DNSCrypt v2 resolver.

**Running the Application:**

By default, `dns2tcp` uses a pre-configured public DNSCrypt resolver (AdGuard DNS):
```bash
# Requires privileges to bind to port 53, often sudo is needed.
sudo ./dns2tcp
```

**Using a Custom DNSCrypt Resolver:**

You can specify a different DNSCrypt v2 resolver using its DNS Stamp string via the `-stamp` command-line flag:
```bash
sudo ./dns2tcp -stamp "sdns://YOUR_DNSCRYPT_STAMP_HERE"
```
Public DNSCrypt resolver stamps can be found on sites like [https://dnscrypt.info/stamps](https://dnscrypt.info/stamps) and other curated lists.

**Testing:**

Once `dns2tcp` is running, you can point a DNS client like `dig` or `nslookup` to `127.0.0.1` to test it:
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
