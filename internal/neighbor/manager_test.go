package neighbor

import (
	"net"
	"testing"
)

// Test NewNeighborManager function
func TestNewNeighborManager(t *testing.T) {
	nm, err := NewNeighborManager("lo")
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	if nm.TargetInterface != "lo" {
		t.Errorf("Expected lo, got %s", nm.TargetInterface)
	}

	if nm.TargetInterfaceIndex != 1 {
		t.Errorf("Expected 1, got %d", nm.TargetInterfaceIndex)
	}
}

func TestNewNeighboerManagerWithInvalidInterface(t *testing.T) {
	nm, err := NewNeighborManager("invalid")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	if nm != nil {
		t.Errorf("Expected nil, got %v", nm)
	}
}

func TestAddNeighbor(t *testing.T) {
	nm, _ := NewNeighborManager("lo")

	ip := net.ParseIP("10.10.10.10")
	nm.AddNeighbor(ip, 1, nil)

	if len(nm.ReachableNeighbors) != 1 {
		t.Errorf("Expected 1, got %d", len(nm.ReachableNeighbors))
	}
}

func TestRemoveNeighbor(t *testing.T) {
	nm, _ := NewNeighborManager("lo")

	ip := net.ParseIP("10.10.10.10")
	nm.AddNeighbor(ip, 1, nil)
	nm.RemoveNeighbor(ip, 1)

	if len(nm.ReachableNeighbors) != 0 {
		t.Errorf("Expected 0, got %d", len(nm.ReachableNeighbors))
	}
}
