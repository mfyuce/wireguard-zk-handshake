# WireGuard ZK Handshake

A modified Linux 6.8 WireGuard kernel module that adds **Schnorr zero-knowledge proof authentication** to the WireGuard handshake. A peer must prove knowledge of a secret key — without revealing it — before the gateway accepts the handshake. A small Rust userspace daemon handles proof generation and verification via Generic Netlink.

This is the reference implementation for the paper:
> *Privacy-Preserving VPN Handshakes with Schnorr-Based Zero-Knowledge Proofs*, Computers & Security 2026.

---

## How It Works

### ZK Scheme

The scheme is a Schnorr proof over Ed25519 (curve25519-dalek):

| Role | Operation |
|------|-----------|
| Client (prover) | `R = r·G`, `c = H("WGZK-v1/schnorr-ed25519" ‖ R)`, `s = r + c·sk` |
| Gateway (verifier) | Accept iff `s·G == R + c·X` (where `X = sk·G` is the known public key) |

### Protocol Flow

```
CLIENT                      KERNEL                       GATEWAY
  |                            |                             |
  | ping 10.20.10.10           |                             |
  |---packet queued----------->|                             |
  |                            |--NEED_PROOF (genl mcast)--->|
  |                            |<---(client daemon)          |
  |<--SET_PROOF (peer_id, r,s)-|                             |
  |                            |--ZK initiation (212 bytes)->|
  |                            |                             |--NEED_VERIFY (genl mcast)
  |                            |                             |<--SET_VERIFY (ok=1)
  |                            |<--handshake response--------|
  |                            |--session established------->|
  |<---------ICMP reply--------|<----------------------------|
```

### Extended Handshake Packet

The kernel module introduces a new packet type (`0xA1`) alongside the standard WireGuard initiation:

```c
struct message_handshake_initiation_zk {   // 212 bytes total
    struct message_header header;           // offset   0, type = 0xA1
    __le32 sender_index;                   // offset   4
    u8 unencrypted_ephemeral[32];          // offset   8
    u8 encrypted_static[48];              // offset  40
    u8 encrypted_timestamp[28];           // offset  88
    u8 zk_r[32];                          // offset 116  ← Schnorr R
    u8 zk_s[32];                          // offset 148  ← Schnorr s
    struct message_macs macs;             // offset 180
} __packed;
```

### Kernel ↔ Daemon Interface

All communication uses the `wgzk` Generic Netlink family:

| Direction | Command | Payload |
|-----------|---------|---------|
| kernel → daemon | `NEED_PROOF` | `ifindex`, `peer_id`, `token` |
| daemon → kernel | `SET_PROOF` | `peer_id`, `token`, `r[32]`, `s[32]`, `ifindex` |
| kernel → daemon | `NEED_VERIFY` | `sender_index`, `r[32]`, `s[32]` |
| daemon → kernel | `SET_VERIFY` | `sender_index`, `result` (0/1) |

---

## Repository Layout

```
wireguard-6.8/          Modified kernel module source
  messages.h              ZK packet struct definitions
  noise.c                 Handshake state machine (ZK proof insertion)
  send.c                  Handshake initiation with ZK / rate-limiter fix
  receive.c               ZK initiation receive + NEED_VERIFY dispatch
  wgzk_genl.c/h           Generic Netlink family (NEED_PROOF, SET_PROOF, …)
  zk_proof.c/h            In-kernel proof cache (peer_id → r/s)
  zk_pending.c/h          Pending handshake table (sender_index → peer)

userspace/
  wg-zk-daemon/           Rust daemon (proof generation + verification)
    src/main.rs             Client + gateway event loops
    src/netlink.rs          neli 0.7 async helpers
    src/zk.rs               Schnorr prove/verify (curve25519-dalek)
  gen-pk/                 Schnorr key-pair generator (Ed25519)

run/
  wg_vm_left.sh           VM setup script — LEFT/client side
  wg_vm_right.sh          VM setup script — RIGHT/gateway side
```

---

## Prerequisites

- Linux **6.8** kernel (Ubuntu 22.04 HWE or equivalent)
- Kernel headers for the running kernel: `sudo apt install linux-headers-$(uname -r)`
- Build tools: `sudo apt install git build-essential libelf-dev`
- **Rust** toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- `libnl-genl` tools (optional, for debugging): `sudo apt install libnl-genl-3-dev`

For the two-VM demo: two machines (physical or virtual) that can reach each other over UDP, both running Linux 6.8.

---

## Building the Kernel Module

### Out-of-tree (quick)

```bash
cd wireguard-6.8
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# .ko is at wireguard-6.8/wireguard.ko
```

### In-tree (recommended for correct symbol resolution)

```bash
# 1. Get the Ubuntu HWE 6.8 kernel source
wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-signed-hwe-6.8/6.8.0-59.61~22.04.1/linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.dsc
wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-signed-hwe-6.8/6.8.0-59.61~22.04.1/linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.tar.xz
sudo dpkg-source -x linux-signed-hwe-6.8_6.8.0-59.61~22.04.1.dsc
cd linux-signed-hwe-6.8-6.8.0
sudo apt install ubuntu-dev-tools
pull-lp-source linux-hwe-6.8
cd linux-hwe-6.8-6.8.0

# 2. Replace the WireGuard driver with this repo's version
mv drivers/net/wireguard drivers/net/wireguard.bck
cp -r /path/to/this-repo/wireguard-6.8 drivers/net/wireguard

# 3. Configure and build
cp /boot/config-$(uname -r) .config
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
make olddefconfig
make modules_prepare
make -C /lib/modules/$(uname -r)/build M=drivers/net/wireguard -j$(nproc) modules
```

The `.ko` ends up at `drivers/net/wireguard/wireguard.ko`.

---

## Building the Daemon

```bash
cd userspace/wg-zk-daemon
cargo build --release
# binary: target/release/wg-zk-daemon
```

### Key Generation

```bash
cd userspace/gen-pk
cargo run --release
# Output:
#   <pk_hex>
#   WGZK_SK_HEX=<sk_hex>
#   WGZK_PK_HEX=<pk_hex>
```

Save `WGZK_SK_HEX` for the client `.env` and `WGZK_PK_HEX` for the gateway `.env`.

---

## Two-VM Demo

This demo uses two VMs with the network layout:

```
LEFT VM (client)                    RIGHT VM (gateway)
  dum0l  10.10.10.10/24               dum0r  10.20.10.10/24
  wg1l   192.168.1.1/32  <=========>  wg1r   192.168.1.2/32
         UDP 10.0.2.8:51821           UDP 10.0.2.7:51921
```

### Step 1 — Load the kernel module on both VMs

Copy `wireguard.ko` to each VM at `/home/m/wireguard.ko`, then:

```bash
sudo modprobe -r wireguard
sudo install -D -m644 /home/m/wireguard.ko /lib/modules/$(uname -r)/extra/wireguard.ko

# Load dependencies
sudo modprobe libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
             curve25519-x86_64 libcurve25519-generic chacha20poly1305 \
             gcm aes_generic aesni_intel af_alg

sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko

# Verify the wgzk netlink family is registered
cat /proc/net/genetlink | grep wgzk
# → wgzk   41   1
```

### Step 2 — Bring up WireGuard interfaces

On **LEFT** VM (adjust `PEER_ENDPOINT` to RIGHT's underlay IP):

```bash
cd /path/to/repo/run
sudo ./wg_vm_left.sh up
```

On **RIGHT** VM:

```bash
cd /path/to/repo/run
sudo ./wg_vm_right.sh up
```

These scripts create the `wg1l`/`wg1r` and `dum0l`/`dum0r` interfaces, configure peers, routes, and disable `rp_filter` so cross-interface traffic is forwarded.

> **Tip:** the first time, run `ensure_keys` manually to exchange public keys between VMs via `scp`.

### Step 3 — Generate a ZK key pair

```bash
cd userspace/gen-pk && cargo run --release
# → WGZK_SK_HEX=<secret>
# → WGZK_PK_HEX=<public>
```

### Step 4 — Create `.env` files

**LEFT VM** — `wg-zk-daemon/.env` (client: holds the secret key):

```dotenv
WGZK_MODE=client
WGZK_SK_HEX=<sk_hex from gen-pk>
```

**RIGHT VM** — `wg-zk-daemon/.env` (gateway: holds the public key):

```dotenv
WGZK_MODE=gateway
WGZK_PK_HEX=<pk_hex from gen-pk>
```

### Step 5 — Start the daemons

On **RIGHT** (gateway) first:

```bash
cd /home/m
./wg-zk-daemon   # reads .env automatically
```

Then on **LEFT** (client):

```bash
cd /home/m
./wg-zk-daemon
```

You should see on the client:

```
[daemon] Starting
[daemon] Keys loaded
[daemon] Mode = client
[wgzk] joined events
```

### Step 6 — Test the tunnel

```bash
# From LEFT VM — use source IP, not device name
ping -I 10.10.10.10 10.20.10.10 -c 5
```

Expected output:

```
PING 10.20.10.10 (10.20.10.10) from 10.10.10.10 : 56(84) bytes of data.
64 bytes from 10.20.10.10: icmp_seq=1 ttl=64 time=0.455 ms
64 bytes from 10.20.10.10: icmp_seq=2 ttl=64 time=0.575 ms
...
5 packets transmitted, 5 received, 0% packet loss
```

#### What you'll see in daemon logs

**Client:**
```
[daemon] NEED_PROOF ifindex=X peer_id=Y token=Z
[client] proving r=<hex> s=<hex>
[daemon] SET_PROOF sent peer_id=Y token=Z
```

**Gateway:**
```
[gateway] r=<hex> s=<hex>
[gateway] verify result=true idx=W
[gateway] SET_VERIFY idx=W result=true
```

---

## Configuration Reference

| Environment variable | Side | Description |
|----------------------|------|-------------|
| `WGZK_MODE` | both | `client` (generates proofs) or `gateway` (verifies proofs) |
| `WGZK_SK_HEX` | client | 32-byte Schnorr secret key, hex-encoded |
| `WGZK_PK_HEX` | gateway | 32-byte Schnorr public key (`X = sk·G`), hex-encoded |

---

## Troubleshooting

### Kernel module fails to load — "Unknown symbol in module"

Load all dependencies first (see Step 1 above). The full list matters; partial modprobe leaves unresolved symbols.

### `wgzk` family not found in `/proc/net/genetlink`

The module did not load completely. Check `dmesg | grep -i wg` for errors.

### Ping: 100% packet loss, but tcpdump on `wg1l` shows packets

Reverse-path filter is dropping replies. Fix:

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
```

The `wg_vm_*.sh up` scripts do this automatically via `rp_off()`.

### Ping using `-I dum0l` (interface name) gives 0% received

`-I <device>` binds the socket to `dum0l`, which is a dummy interface — packets never reach the WireGuard tunnel. Use the source IP instead:

```bash
ping -I 10.10.10.10 10.20.10.10   # ✓ correct
ping -I dum0l 10.20.10.10          # ✗ wrong — binds to dummy device
```

### Daemon reconnects every second

Versions prior to the `recv_next` fix treated ACK frames from `SET_PROOF`/`SET_VERIFY` as fatal errors, tearing down the socket. Ensure you are running the patched `netlink.rs` where `NlPayload::Ack` is handled with `continue` (not returned as `Err`).

### First ping always drops, subsequent succeed

This is expected on first handshake (the proof cache is cold). The kernel emits `NEED_PROOF`, the daemon responds with `SET_PROOF`, then the handshake retries immediately. The `atomic64_set(&peer->last_sent_handshake, 0)` fix in `send.c` ensures the retry is not rate-limited.

---

## Key Design Notes

- **No changes to the Noise protocol**: the Schnorr proof sits alongside the existing Noise fields; `zk_r`/`zk_s` are appended after `encrypted_timestamp` and before `macs` in a new packet type (`0xA1`). The Noise handshake itself is unchanged.
- **Proof is single-use**: `zk_proof_get_and_clear` in the kernel removes the cached proof after one use, preventing replay.
- **Rate-limiter fix**: when the proof cache is empty, `last_sent_handshake` is reset to 0 so the daemon's immediate `SET_PROOF` triggers a retry without waiting `REKEY_TIMEOUT` (5 s).
- **Both roles in one binary**: the daemon runs client and gateway loops concurrently; `WGZK_MODE` only controls which key is loaded and which log messages appear.

---

## License

GPL-2.0 (kernel module). See [COPYING](COPYING).
The Rust userspace daemon is MIT/Apache-2.0 (Rust ecosystem crates).
