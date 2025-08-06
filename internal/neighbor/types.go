package neighbor

import (
	"net"
	"sync"
)

type NeighborManager struct {
	mu                   sync.Mutex
	reachableNeighbors   map[string]Neighbor
	targetInterface      string
	targetInterfaceIndex int
}

type Neighbor struct {
	IP           net.IP
	LinkIndex    int
	HardwareAddr net.HardwareAddr
}
