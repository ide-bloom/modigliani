# Capture setups

Every setup starts the same way:

```powershell
modigliani ca init            # needed for proxy mode and for reviving TLS devices
modigliani enroll             # choose your device; you must confirm you own it
```

Enrollment keys on MAC and IP address. Only enrolled devices are resolved, proxied or recorded.
Live capture applies a BPF filter, so other clients' frames never reach Modigliani. pcap import
drops them while reading. The proxy closes their connections. Router-mode DNS forwards their
queries without recording them.

While recording, run `modigliani annotate` (it attaches to the capture in progress) and describe
each action right after you do it in the vendor app:

| You do | You type |
|---|---|
| Switch on / off | `turned on`, `turned off` |
| Set a temperature | `set 22 C` |
| Change a mode | `mode cool` |
| Read a value shown in the app | `app shows temperature 21.5 C` |
| Anything, explicitly | `fan=3` |

With several devices in one capture, pass `--device NAME` (CLI) so each annotation applies only
to its device.

## Windows hotspot mode

1. Install [Npcap](https://npcap.com/#download) with *WinPcap API-compatible mode*.
   `modigliani doctor` checks for it.
2. Turn on *Settings > Network & internet > Mobile hotspot* and join the device to it through the
   vendor app. Windows gives the hotspot adapter the address 192.168.137.1.
3. `modigliani enroll`: the device appears in the ARP table list.
4. `modigliani record --mode passive --minutes 15 --name plug`.

Passive capture reads plaintext protocols completely. For TLS it keeps only the SNI, sizes and
timing, and the profile reports those hosts as *untested*. To find out whether the device
accepts the local CA, record it again in proxy mode.

## Router mode

Configure your router to send the device's DNS to this PC. For example, set a static DHCP DNS
option for that client, or add a dnsmasq `dhcp-option` tag. Then run:

```powershell
modigliani record --mode proxy --dns --dns-answer 192.168.1.10 `
    --route https:443=* --route tls:8883=* --route http:80=* --route udp:5683=coap.vendor.example
```

- `--dns` answers enrolled devices on UDP port 53 (`--dns-port` changes it). Queries are
  resolved upstream (`--dns-upstream`, default 1.1.1.1) so the real addresses are known. The
  device receives `--dns-answer`, this PC's address.
- Routes use the syntax `SCHEME:[LISTEN_HOST:]PORT=HOSTNAME[@UPSTREAM_HOST:PORT]`, with
  `SCHEME` one of `https`, `http`, `tls` (MQTT/TLS and other TLS protocols), `tcp` or `udp`.
  `HOSTNAME` `*` means "the host the device asked for": the TLS SNI, or the HTTP Host header for
  `http`. The connection goes to its real address as learned by the DNS responder.
- TLS connections are terminated with a certificate from the local CA. A device that refuses it
  is recorded as `rejected_local_ca`, and its later connections to that host are passed through
  untouched (metadata only).

## Gateway mode

A Linux box with two interfaces sits between the device and the network (for example a
Raspberry Pi acting as a Wi-Fi access point). Capture on its device-side interface:

```bash
sudo modigliani record --mode passive --interface wlan0 --minutes 15 --name plug
```

When the cloud is gone, run Modigliani Server on the same box and enable its DNS responder
(`dns.listen`, `dns.answer_ip`; see [server.md](server.md)) so that the device resolves vendor
names to the box.

## Import

Capture on your router and import the file:

```bash
# OpenWrt (install tcpdump-mini first)
tcpdump -i br-lan -s 0 -w /tmp/plug.pcap host 192.168.1.20
```

```powershell
modigliani import plug.pcap
```

Import reassembles TCP streams (out-of-order segments and retransmissions included), records DNS
answers to name servers, and keeps encrypted sessions as metadata only.

## Localhost port mapping (development and CI)

The end-to-end tests run every device on one machine. Each simulated device connects from its
own loopback address (127.0.0.2 to 127.0.0.5), so enrollment by IP behaves as on a hotspot.
Routes with explicit upstreams map local ports to the vendor-cloud simulators:

```text
--route https:127.0.0.1:18443=api.smartplug.example@127.0.0.1:28443
```

`--upstream-ca` lets proxy mode verify a test vendor's certificate authority.
