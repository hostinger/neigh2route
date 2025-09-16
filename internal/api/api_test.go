package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/neigh2route/internal/neighbor"
)

// Helper function to parse hardware address
func parseMAC(s string) net.HardwareAddr {
	mac, _ := net.ParseMAC(s)
	return mac
}

// Helper function to create API with populated neighbor manager
func createAPIWithNeighbors(neighbors map[string]neighbor.Neighbor) *API {
	nm, _ := neighbor.NewNeighborManager("lo")

	for _, n := range neighbors {
		nm.ReachableNeighbors[n.IP.String()] = n
	}

	return &API{NM: nm}
}

func TestListNeighborsHandler_Success(t *testing.T) {
	// Prepare fake neighbor data
	neighbors := map[string]neighbor.Neighbor{
		"192.168.1.10": {
			IP:           net.ParseIP("192.168.1.10"),
			LinkIndex:    2,
			HardwareAddr: parseMAC("00:11:22:33:44:55"),
		},
		"192.168.1.20": {
			IP:           net.ParseIP("192.168.1.20"),
			LinkIndex:    3,
			HardwareAddr: parseMAC("aa:bb:cc:dd:ee:ff"),
		},
		"2001:db8::1": {
			IP:           net.ParseIP("2001:db8::1"),
			LinkIndex:    4,
			HardwareAddr: parseMAC("11:22:33:44:55:66"),
		},
	}

	api := createAPIWithNeighbors(neighbors)

	req := httptest.NewRequest("GET", "/neighbors", nil)
	rr := httptest.NewRecorder()

	api.ListNeighborsHandler(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check content type
	expectedContentType := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	// Parse response
	var response struct {
		Neighbors []struct {
			IP           string `json:"ip"`
			LinkIndex    int    `json:"link_index"`
			HardwareAddr string `json:"hwAddr"`
			Afi          string `json:"afi"`
		} `json:"neighbors"`
		Count     int       `json:"count"`
		Timestamp time.Time `json:"timestamp"`
	}

	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Could not unmarshal response: %v", err)
	}

	// Verify response structure
	if response.Count != 3 {
		t.Errorf("Expected count 3, got %d", response.Count)
	}

	if len(response.Neighbors) != 3 {
		t.Errorf("Expected 3 neighbors, got %d", len(response.Neighbors))
	}

	// Verify neighbors are sorted by IP
	expectedOrder := []string{"192.168.1.10", "192.168.1.20", "2001:db8::1"}
	for i, expected := range expectedOrder {
		if response.Neighbors[i].IP != expected {
			t.Errorf("Expected neighbor %d to be %s, got %s", i, expected, response.Neighbors[i].IP)
		}
	}

	// Verify AFI classification
	v4Count := 0
	v6Count := 0
	for _, n := range response.Neighbors {
		if n.Afi == "v4" {
			v4Count++
		} else if n.Afi == "v6" {
			v6Count++
		}
	}

	if v4Count != 2 {
		t.Errorf("Expected 2 IPv4 neighbors, got %d", v4Count)
	}

	if v6Count != 1 {
		t.Errorf("Expected 1 IPv6 neighbor, got %d", v6Count)
	}
}

func TestListNeighborsHandler_EmptyList(t *testing.T) {
	// Test with empty neighbor list
	api := createAPIWithNeighbors(map[string]neighbor.Neighbor{})

	req := httptest.NewRequest("GET", "/neighbors", nil)
	rr := httptest.NewRecorder()

	api.ListNeighborsHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response struct {
		Neighbors []interface{} `json:"neighbors"`
		Count     int           `json:"count"`
		Timestamp time.Time     `json:"timestamp"`
	}

	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Could not unmarshal response: %v", err)
	}

	if response.Count != 0 {
		t.Errorf("Expected count 0, got %d", response.Count)
	}

	if len(response.Neighbors) != 0 {
		t.Errorf("Expected 0 neighbors, got %d", len(response.Neighbors))
	}
}

func TestListNeighborsHandler_MethodNotAllowed(t *testing.T) {
	api := createAPIWithNeighbors(map[string]neighbor.Neighbor{})

	// Test POST method (should not be allowed)
	req := httptest.NewRequest("POST", "/neighbors", strings.NewReader("{}"))
	rr := httptest.NewRecorder()

	api.ListNeighborsHandler(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}

	var errorResponse ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Could not unmarshal error response: %v", err)
	}

	if errorResponse.Error != "method_not_allowed" {
		t.Errorf("Expected error 'method_not_allowed', got %s", errorResponse.Error)
	}

	if errorResponse.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected code %d, got %d", http.StatusMethodNotAllowed, errorResponse.Code)
	}
}

func TestListSniffedInterfacesHandler_Success(t *testing.T) {
	// Since sniffer.ListActiveSniffers() is a global function, we test with real implementation
	api := &API{NM: nil} // We don't need NM for this test

	req := httptest.NewRequest("GET", "/sniffers", nil)
	rr := httptest.NewRecorder()

	api.ListSniffedInterfacesHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, "application/json")
	}

	var response struct {
		Interfaces []struct {
			Interface string        `json:"interface"`
			StartedAt time.Time     `json:"started_at"`
			Uptime    time.Duration `json:"uptime_seconds"`
		} `json:"interfaces"`
		Count     int       `json:"count"`
		Timestamp time.Time `json:"timestamp"`
	}

	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Could not unmarshal response: %v", err)
	}

	// With no active sniffers, count should be 0
	if response.Count != 0 {
		t.Errorf("Expected count 0, got %d", response.Count)
	}

	if len(response.Interfaces) != 0 {
		t.Errorf("Expected 0 interfaces, got %d", len(response.Interfaces))
	}
}

func TestListSniffedInterfacesHandler_MethodNotAllowed(t *testing.T) {
	api := &API{NM: nil}

	// Test PUT method (should not be allowed)
	req := httptest.NewRequest("PUT", "/sniffers", strings.NewReader("{}"))
	rr := httptest.NewRecorder()

	api.ListSniffedInterfacesHandler(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}

	var errorResponse ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Could not unmarshal error response: %v", err)
	}

	if errorResponse.Error != "method_not_allowed" {
		t.Errorf("Expected error 'method_not_allowed', got %s", errorResponse.Error)
	}
}

func TestAllMethodNotAllowed(t *testing.T) {
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run("ListNeighbors_"+method, func(t *testing.T) {
			api := createAPIWithNeighbors(map[string]neighbor.Neighbor{})
			req := httptest.NewRequest(method, "/neighbors", nil)
			rr := httptest.NewRecorder()

			api.ListNeighborsHandler(rr, req)

			if status := rr.Code; status != http.StatusMethodNotAllowed {
				t.Errorf("Expected %d, got %d for method %s", http.StatusMethodNotAllowed, status, method)
			}
		})

		t.Run("ListSniffers_"+method, func(t *testing.T) {
			api := &API{NM: nil}
			req := httptest.NewRequest(method, "/sniffers", nil)
			rr := httptest.NewRecorder()

			api.ListSniffedInterfacesHandler(rr, req)

			if status := rr.Code; status != http.StatusMethodNotAllowed {
				t.Errorf("Expected %d, got %d for method %s", http.StatusMethodNotAllowed, status, method)
			}
		})
	}
}

func TestWriteErrorResponse(t *testing.T) {
	testCases := []struct {
		code    int
		error   string
		message string
	}{
		{http.StatusBadRequest, "test_error", "Test error message"},
		{http.StatusNotFound, "not_found", "Resource not found"},
		{http.StatusInternalServerError, "internal_error", "Something went wrong"},
		{http.StatusUnauthorized, "unauthorized", "Authentication required"},
	}

	for _, tc := range testCases {
		t.Run("writeErrorResponse", func(t *testing.T) {
			rr := httptest.NewRecorder()

			writeErrorResponse(rr, tc.code, tc.error, tc.message)

			if status := rr.Code; status != tc.code {
				t.Errorf("writeErrorResponse set wrong status code: got %v want %v", status, tc.code)
			}

			if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("writeErrorResponse set wrong content type: got %v want %v", contentType, "application/json")
			}

			var errorResponse ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
				t.Fatalf("Could not unmarshal error response: %v", err)
			}

			if errorResponse.Error != tc.error {
				t.Errorf("Expected error '%s', got '%s'", tc.error, errorResponse.Error)
			}

			if errorResponse.Message != tc.message {
				t.Errorf("Expected message '%s', got '%s'", tc.message, errorResponse.Message)
			}

			if errorResponse.Code != tc.code {
				t.Errorf("Expected code %d, got %d", tc.code, errorResponse.Code)
			}
		})
	}
}

func TestWriteJSONResponse_Success(t *testing.T) {
	rr := httptest.NewRecorder()

	testData := map[string]interface{}{
		"test":  "value",
		"count": 42,
	}

	writeJSONResponse(rr, testData)

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("writeJSONResponse set wrong content type: got %v want %v", contentType, "application/json")
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Could not unmarshal response: %v", err)
	}

	if response["test"] != "value" {
		t.Errorf("Expected test field to be 'value', got %v", response["test"])
	}

	if response["count"].(float64) != 42 {
		t.Errorf("Expected count field to be 42, got %v", response["count"])
	}
}

func TestWriteJSONResponse_Nil(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, nil)

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("writeJSONResponse set wrong content type: got %v want %v", contentType, "application/json")
	}

	body := rr.Body.String()
	if body != "null\n" {
		t.Errorf("Expected 'null\\n', got %s", body)
	}
}
