package neighbor

import (
	"net"
	"sync"
	"time"

	"github.com/tomvil/neigh2route/internal/logger"
	"github.com/tomvil/neigh2route/pkg/netutils"
	"github.com/vishvananda/netlink"
)

func NewNeighborManager(targetInterface string) (*NeighborManager, error) {
	nm := &NeighborManager{
		targetInterface:    targetInterface,
		reachableNeighbors: make(map[string]Neighbor),
	}

	if targetInterface != "" {
		iface, err := netlink.LinkByName(targetInterface)
		if err != nil {
			return nil, err
		}
		nm.targetInterfaceIndex = iface.Attrs().Index
	} else {
		nm.targetInterfaceIndex = -1
	}

	return nm, nil
}

func (n Neighbor) LinkIndexChanged(linkIndex int) bool {
	return n.linkIndex != linkIndex
}

func (nm *NeighborManager) AddNeighbor(ip net.IP, linkIndex int) {
	var shouldRemoveRoute bool

	nm.mu.Lock()
	neighbor, exists := nm.reachableNeighbors[ip.String()]
	if exists {
		if !neighbor.LinkIndexChanged(linkIndex) {
			nm.mu.Unlock()
			return
		}
		logger.Info("Neighbor %s link index changed, re-adding neighbor", ip.String())
		shouldRemoveRoute = true
	}

	if shouldRemoveRoute {
		err := netutils.RemoveRoute(ip, neighbor.linkIndex)
		if err != nil {
			logger.Error("Failed to remove old route for neighbor %s: %v", ip.String(), err)
			return
		}
	}

	nm.reachableNeighbors[ip.String()] = Neighbor{ip: ip, linkIndex: linkIndex}
	nm.mu.Unlock()

	if err := netutils.AddRoute(ip, linkIndex); err != nil {
		logger.Error("Failed to add route for neighbor %s: %v", ip.String(), err)
		return
	}

	logger.Info("Added neighbor %s", ip.String())
}

func (nm *NeighborManager) RemoveNeighbor(ip net.IP, linkIndex int) {
	var shouldRemoveRoute bool

	nm.mu.Lock()
	if _, exists := nm.reachableNeighbors[ip.String()]; exists {
		delete(nm.reachableNeighbors, ip.String())
		logger.Info("Removed neighbor %s", ip.String())
		shouldRemoveRoute = true
	}
	nm.mu.Unlock()

	if shouldRemoveRoute {
		if err := netutils.RemoveRoute(ip, linkIndex); err != nil {
			logger.Error("Failed to remove route for neighbor %s: %v", ip.String(), err)
			return
		}
	}
}

func (nm *NeighborManager) isNeighborExternallyLearned(flags int) bool {
	return flags&netlink.NTF_EXT_LEARNED != 0
}

func (nm *NeighborManager) InitializeNeighborTable() error {
	interfaceIndex := 0
	if nm.targetInterfaceIndex >= 0 {
		interfaceIndex = nm.targetInterfaceIndex
	}

	neighbors, err := netlink.NeighList(interfaceIndex, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	logger.Info("Initializing neighbor table with %d neighbors", len(neighbors))

	for _, n := range neighbors {
		if n.IP.IsLinkLocalUnicast() {
			logger.Info("Skipping link-local neighbor with IP=%s, LinkIndex=%d", n.IP, n.LinkIndex)
			continue
		}

		if (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE)) != 0 && !nm.isNeighborExternallyLearned(n.Flags) {
			logger.Info("Adding neighbor with IP=%s, LinkIndex=%d", n.IP, n.LinkIndex)
			nm.AddNeighbor(n.IP, n.LinkIndex)
		}
	}

	logger.Info("Neighbor table initialized finished")

	return nil
}

func (nm *NeighborManager) MonitorNeighbors() {
	updates := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.NeighSubscribe(updates, done); err != nil {
		logger.Error("Failed to subscribe to neighbor updates: %v (interface: %s, index: %d)",
			err, nm.targetInterface, nm.targetInterfaceIndex)
	}

	for update := range updates {
		if nm.targetInterfaceIndex > 0 && update.Neigh.LinkIndex != nm.targetInterfaceIndex {
			continue
		}

		if update.Neigh.IP.IsLinkLocalUnicast() {
			continue
		}

		logger.Debug("Received neighbor update: IP=%s, State=%s, Flags=%s, LinkIndex=%d",
			update.Neigh.IP, neighborStateToString(update.Neigh.State), neighborFlagsToString(update.Neigh.Flags), update.Neigh.LinkIndex)

		if (update.Neigh.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE)) != 0 && !nm.isNeighborExternallyLearned(update.Neigh.Flags) {
			nm.AddNeighbor(update.Neigh.IP, update.Neigh.LinkIndex)
		}

		if update.Neigh.State == netlink.NUD_FAILED || nm.isNeighborExternallyLearned(update.Neigh.Flags) {
			nm.RemoveNeighbor(update.Neigh.IP, update.Neigh.LinkIndex)
		}
	}
}

func (nm *NeighborManager) SendPings() {
	for {
		var wg sync.WaitGroup

		nm.mu.Lock()
		neighbors := make([]Neighbor, 0, len(nm.reachableNeighbors))

		for _, n := range nm.reachableNeighbors {
			neighbors = append(neighbors, n)
		}
		nm.mu.Unlock()

		for _, n := range neighbors {
			wg.Add(1)
			go func(n Neighbor) {
				defer wg.Done()
				if err := netutils.Ping(n.ip.String()); err != nil {
					logger.Error("Failed to ping neighbor %s: %v", n.ip.String(), err)
				}
			}(n)
		}
		wg.Wait()

		<-time.After(30 * time.Second)
	}
}

func (nm *NeighborManager) Cleanup() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for _, n := range nm.reachableNeighbors {
		if err := netutils.RemoveRoute(n.ip, n.linkIndex); err != nil {
			logger.Error("Failed to remove route for neighbor %s: %v", n.ip.String(), err)
			continue
		}
		logger.Info("Removed route for neighbor %s", n.ip.String())
	}
}
