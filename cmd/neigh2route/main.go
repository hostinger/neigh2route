package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tomvil/neigh2route/internal/api"
	"github.com/tomvil/neigh2route/internal/logger"
	"github.com/tomvil/neigh2route/internal/neighbor"
	"github.com/tomvil/neigh2route/internal/sniffer"
)

var (
	snifferMode     = flag.Bool("sniffer", false, "Enable NA sniffer mode for tap interfaces")
	listenInterface = flag.String("interface", "", "Interface to monitor for neighbor updates")
	apiAddress      = flag.String("port", "127.0.0.1:54321", "Port for the API server")
	debugMode       = flag.Bool("debug", false, "Enable debug logging")
)

func main() {
	flag.Parse()

	if *snifferMode {
		if *listenInterface == "" {
			logger.Fatal("You must specify --interface when using --sniffer")
		}
		go sniffer.StartSnifferManager(*listenInterface)
	}

	logger.Init(*debugMode)

	nm, err := neighbor.NewNeighborManager(*listenInterface)
	if err != nil {
		logger.Fatal("Failed to initialize neighbor manager: %v", err)
	}

	if err := nm.InitializeNeighborTable(); err != nil {
		logger.Error("Failed to initialize neighbor table: %v", err)
	}

	api := &api.API{NM: nm}
	http.HandleFunc("/neighbors", api.ListNeighborsHandler)

	go func() {
		logger.Info("API server listening on %s", *apiAddress)
		if err := http.ListenAndServe(*apiAddress, nil); err != nil {
			logger.Error("HTTP server failed: %v", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		logger.Info("Received signal: %s. Cleaning up and exiting...", sig)
		nm.Cleanup()
		os.Exit(0)
	}()

	go nm.SendPings()

	nm.MonitorNeighbors()
}
