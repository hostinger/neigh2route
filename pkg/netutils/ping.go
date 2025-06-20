package netutils

import (
	"time"

	"github.com/go-ping/ping"
	"github.com/hostinger/neigh2route/internal/logger"
)

func Ping(ip string) error {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		logger.Error("failed to create pinger: %w", err)
		return err
	}

	pinger.Count = 3
	pinger.Timeout = time.Second * 5
	pinger.Interval = time.Second * 1
	pinger.SetPrivileged(true)

	err = pinger.Run()
	if err != nil {
		logger.Error("failed to run pinger: %w", err)
		return err
	}

	return nil
}
