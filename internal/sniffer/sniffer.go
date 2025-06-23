package sniffer

import (
	"context"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hostinger/neigh2route/internal/logger"
	"github.com/vishvananda/netlink"
)

type SnifferInfo struct {
	CancelFunc context.CancelFunc
	StartedAt  time.Time
}

var (
	activeSniffersMu sync.Mutex
	activeSniffers   = make(map[string]SnifferInfo)
)

func ListActiveSniffers() map[string]time.Time {
	activeSniffersMu.Lock()
	defer activeSniffersMu.Unlock()

	result := make(map[string]time.Time)
	for iface, info := range activeSniffers {
		result[iface] = info.StartedAt
	}
	return result
}

func neighborAlreadyValid(ip net.IP) (bool, string) {
	neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		logger.Error("[Sniffer-Event] Failed to get neighbor list: %v", err)
		return false, ""
	}

	for _, neigh := range neighbors {
		if neigh.IP.Equal(ip) {
			switch neigh.State {
			case netlink.NUD_REACHABLE:
				return true, "REACHABLE"
			case netlink.NUD_STALE:
				return true, "STALE"
			case netlink.NUD_DELAY:
				return true, "DELAY"
			case netlink.NUD_PROBE:
				return true, "PROBE"
			}
		}
	}
	return false, ""
}

func addNeighborEntry(ip net.IP, mac net.HardwareAddr, sniffIface string) {
	link, err := netlink.LinkByName(sniffIface)
	if err != nil {
		logger.Error("[Sniffer-Event] Could not find interface %s: %v", sniffIface, err)
		return
	}

	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           ip,
		HardwareAddr: mac,
		State:        netlink.NUD_REACHABLE,
		Family:       netlink.FAMILY_V6,
	}

	if err := netlink.NeighSet(neigh); err != nil {
		logger.Error("[Sniffer-Event] Failed to set neighbor entry for %s: %v", ip.String(), err)
	} else {
		logger.Info("[Sniffer-Event] Added neighbor entry: %s → %s on %s", ip.String(), mac.String(), sniffIface)
	}
}

func handlePacket(packet gopacket.Packet, sniffIface string, insertIface string) {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)

	if ipv6Layer == nil || icmpv6Layer == nil {
		return
	}

	ipv6 := ipv6Layer.(*layers.IPv6)
	icmpv6 := icmpv6Layer.(*layers.ICMPv6NeighborAdvertisement)
	srcIP := ipv6.SrcIP
	targetIP := icmpv6.TargetAddress

	if srcIP.IsLinkLocalUnicast() || targetIP.IsLinkLocalUnicast() {
		return
	}

	if exists, state := neighborAlreadyValid(targetIP); exists {
		logger.Debug("[Sniffer-Event] [%s] Skipping %s — neighbor already exists with state %s", sniffIface, targetIP.String(), state)
		return
	}

	var mac net.HardwareAddr
	payload := icmpv6Layer.LayerPayload()
	if len(payload) >= 8 && payload[0] == 2 {
		mac = net.HardwareAddr(payload[2:8])
	} else if ethLayer != nil {
		mac = ethLayer.(*layers.Ethernet).SrcMAC
		logger.Debug("[Sniffer-Event] [%s] No DLO in NA, using Ethernet src MAC: %s", sniffIface, mac.String())
	} else {
		logger.Debug("[Sniffer-Event] [%s] NA received but no MAC info available", sniffIface)
		return
	}

	addNeighborEntry(targetIP, mac, insertIface)
}

func sniffNAWithContext(ctx context.Context, sniffIface string, insertIface string) {
	for attempt := 0; attempt < 10; attempt++ {
		link, err := netlink.LinkByName(sniffIface)
		if err == nil && (link.Attrs().Flags&net.FlagUp) != 0 {
			break
		}
		logger.Info("[Sniffer-Event] Waiting for %s to become UP... (%d/10)", sniffIface, attempt+1)
		select {
		case <-ctx.Done():
			logger.Info("[Sniffer-Event] Aborting sniffer start on %s — context cancelled", sniffIface)
			return
		case <-time.After(1 * time.Second):
		}
	}

	handle, err := pcap.OpenLive(sniffIface, 1600, true, pcap.BlockForever)
	if err != nil {
		logger.Error("[Sniffer-Event] Error opening interface %s: %v", sniffIface, err)
		return
	}
	defer handle.Close()

	filter := "inbound and icmp6 and ip6[40] == 136"
	if err := handle.SetBPFFilter(filter); err != nil {
		logger.Error("[Sniffer-Event] Error setting BPF filter on %s: %v", sniffIface, err)
		return
	}

	logger.Info("[Sniffer-Event] Listening for NA packets on %s", sniffIface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			logger.Info("[Sniffer-Event] Stopping sniffer on %s", sniffIface)
			return
		case pkt := <-packetChan:
			if pkt == nil {
				return
			}
			handlePacket(pkt, sniffIface, insertIface)
		}
	}
}

func getTapInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net/")
	if err != nil {
		logger.Fatal("[Sniffer-Event] Failed to list interfaces: %v", err)
	}

	var tapIfaces []string
	re := regexp.MustCompile(`^tap\d+`)
	for _, entry := range entries {
		if re.MatchString(entry.Name()) {
			tapIfaces = append(tapIfaces, entry.Name())
		}
	}
	return tapIfaces
}

func StartSnifferManager(targetIface string) {
	logger.Info("Starting NA sniffer. Scanning for tap interfaces every 30 seconds...")

	for {
		currentIfaces := getTapInterfaces()
		currentSet := make(map[string]bool)
		for _, sniffIface := range currentIfaces {
			currentSet[sniffIface] = true
		}

		for sniffIface := range currentSet {
			if _, exists := activeSniffers[sniffIface]; !exists {
				logger.Info("[Sniffer-Event] New tap detected: %s — starting sniffer", sniffIface)
				ctx, cancel := context.WithCancel(context.Background())
				activeSniffersMu.Lock()
				activeSniffers[sniffIface] = SnifferInfo{
					CancelFunc: cancel,
					StartedAt:  time.Now(),
				}
				activeSniffersMu.Unlock()
				go sniffNAWithContext(ctx, sniffIface, targetIface)
			}
		}

		for sniffIface, info := range activeSniffers {
			if !currentSet[sniffIface] {
				logger.Info("[Sniffer-Event] Tap removed: %s — stopping sniffer", sniffIface)
				info.CancelFunc()
				activeSniffersMu.Lock()
				delete(activeSniffers, sniffIface)
				activeSniffersMu.Unlock()
			}
		}

		time.Sleep(30 * time.Second)
	}
}
