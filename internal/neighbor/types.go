package neighbor

import (
	"net"
	"sync"
)

type NeighborManager struct {
	mu                   sync.Mutex
	ReachableNeighbors   map[string]Neighbor
	TargetInterface      string
	TargetInterfaceIndex int
}

type Neighbor struct {
	IP           net.IP
	LinkIndex    int
	HardwareAddr net.HardwareAddr
}
