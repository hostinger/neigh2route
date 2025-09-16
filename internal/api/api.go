package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/hostinger/neigh2route/internal/logger"
	"github.com/hostinger/neigh2route/internal/neighbor"
	"github.com/hostinger/neigh2route/internal/sniffer"
)

type API struct {
	NM *neighbor.NeighborManager
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, errorMsg string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorMsg,
		Message: details,
		Code:    statusCode,
	})
	if err != nil {
		logger.Error("Failed to encode error response: %v", err)
	}
}

func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("Failed to encode JSON response: %v", err)
		writeErrorResponse(w, http.StatusInternalServerError, "encoding_error", "Failed to encode response")
	}
}

func (a *API) ListNeighborsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	type NeighborView struct {
		IP           string `json:"ip"`
		LinkIndex    int    `json:"link_index"`
		HardwareAddr string `json:"hwAddr"`
		Afi          string `json:"afi"`
	}

	type NeighborsResponse struct {
		Neighbors []NeighborView `json:"neighbors"`
		Count     int            `json:"count"`
		Timestamp time.Time      `json:"timestamp"`
	}

	neighbors := a.NM.ListNeighbors()
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

	response := NeighborsResponse{
		Neighbors: output,
		Count:     len(output),
		Timestamp: time.Now(),
	}

	writeJSONResponse(w, response)
}

func (a *API) ListSniffedInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	type SniffedInterface struct {
		Interface string        `json:"interface"`
		StartedAt time.Time     `json:"started_at"`
		Uptime    time.Duration `json:"uptime_seconds"`
	}

	type SniffersResponse struct {
		Interfaces []SniffedInterface `json:"interfaces"`
		Count      int                `json:"count"`
		Timestamp  time.Time          `json:"timestamp"`
	}

	now := time.Now()
	var sniffed []SniffedInterface

	for iface, started := range sniffer.ListActiveSniffers() {
		sniffed = append(sniffed, SniffedInterface{
			Interface: iface,
			StartedAt: started,
			Uptime:    now.Sub(started),
		})
	}

	sort.Slice(sniffed, func(i, j int) bool {
		return sniffed[i].Interface < sniffed[j].Interface
	})

	response := SniffersResponse{
		Interfaces: sniffed,
		Count:      len(sniffed),
		Timestamp:  now,
	}

	writeJSONResponse(w, response)
}
