package api

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/tomvil/neigh2route/internal/neighbor"
)

type API struct {
	NM *neighbor.NeighborManager
}

func (a *API) ListNeighborsHandler(w http.ResponseWriter, r *http.Request) {
	neighbors := a.NM.ListNeighbors()

	type NeighborView struct {
		IP        string `json:"ip"`
		LinkIndex int    `json:"link_index"`
	}

	var output []NeighborView
	for _, n := range neighbors {
		output = append(output, NeighborView{
			IP:        n.IP.String(),
			LinkIndex: n.LinkIndex,
		})
	}

	sort.Slice(output, func(i, j int) bool {
		return output[i].IP < output[j].IP
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}
