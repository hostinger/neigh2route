# neigh2route

**neigh2route** is a small tool that listens for neighbor updates and adds corresponding static routes on Linux.

## 🚀 What It Does

When a new neighbor is detected on an interface (e.g. `vmbr0`), it adds static route to that interface.

This allows you to easily redistribute dynamic neighbors via BGP or other routing protocols.

## 📌 Example

If `ip neigh` shows: 

`10.10.10.10 dev vmbr0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`

Then `neigh2route` adds:

`ip route add 10.10.10.10/32 dev vmbr0`

## 💡 Use Cases
- Announce your neighbors via dynamic routing protocols, like BGP.

## Dependencies

libpcap-dev must be installed if you want to use sniffer feature