package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/hostinger/neigh2route/internal/neighbor"
	"github.com/hostinger/neigh2route/internal/sniffer"
)

type API struct {
	NM *neighbor.NeighborManager
}

func (a *API) ListNeighborsHandler(w http.ResponseWriter, r *http.Request) {
	neighbors := a.NM.ListNeighbors()

	type NeighborView struct {
		IP           string `json:"ip"`
		LinkIndex    int    `json:"link_index"`
		HardwareAddr string `json:"hwAddr"`
		Afi          string `json:"afi"`
	}

	var output []NeighborView
	for _, n := range neighbors {
		afi := "v4"
		if n.IP.To4() == nil {
			afi = "v6"
		}

		output = append(output, NeighborView{
			IP:           n.IP.String(),
			LinkIndex:    n.LinkIndex,
			HardwareAddr: n.HardwareAddr.String(),
			Afi:          afi,
		})
	}

	sort.Slice(output, func(i, j int) bool {
		return output[i].IP < output[j].IP
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func (a *API) ListSniffedInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	type SniffedInterface struct {
		Interface string    `json:"interface"`
		StartedAt time.Time `json:"started_at"`
	}

	var sniffed []SniffedInterface
	for iface, started := range sniffer.ListActiveSniffers() {
		sniffed = append(sniffed, SniffedInterface{
			Interface: iface,
			StartedAt: started,
		})
	}

	sort.Slice(sniffed, func(i, j int) bool {
		return sniffed[i].Interface < sniffed[j].Interface
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sniffed)
}
