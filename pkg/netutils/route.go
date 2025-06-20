package netutils

import (
	"net"

	"github.com/hostinger/neigh2route/internal/logger"
	"github.com/vishvananda/netlink"
)

func routeExists(dst *net.IPNet, linkIndex int) (bool, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
	}, netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
	if err != nil {
		logger.Error("Failed to list routes for dst %s on link %d: %w", dst.String(), linkIndex, err)
		return false, err
	}

	if len(routes) == 0 {
		logger.Info("No routes found for dst %s on link index %d", dst.String(), linkIndex)
		return false, nil
	}

	logger.Info("Found %d routes for dst %s on link index %d", len(routes), dst.String(), linkIndex)
	return true, nil
}

func AddRoute(ip net.IP, linkIndex int) error {
	mask := net.CIDRMask(32, 32)
	if ip.To4() == nil {
		mask = net.CIDRMask(128, 128)
	}

	routeDst := &net.IPNet{IP: ip, Mask: mask}

	exists, err := routeExists(routeDst, linkIndex)
	if err != nil {
		logger.Error("Failed to check if route exists for %s: %w", ip.String(), err)
		return err
	}

	if exists {
		return nil
	}

	route := &netlink.Route{
		LinkIndex: linkIndex,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: ip, Mask: mask},
	}

	if err := netlink.RouteAdd(route); err != nil {
		logger.Error("Failed to add route for %s: %w", ip.String(), err)
		return err
	}

	logger.Info("Added route for %s on link index %d", ip.String(), linkIndex)
	return nil
}

func RemoveRoute(ip net.IP, linkIndex int) error {
	mask := net.CIDRMask(32, 32)
	if ip.To4() == nil {
		mask = net.CIDRMask(128, 128)
	}

	routeDst := &net.IPNet{IP: ip, Mask: mask}

	exists, err := routeExists(routeDst, linkIndex)
	if err != nil {
		logger.Error("Failed to check if route exists for %s: %w", ip.String(), err)
		return err
	}

	if !exists {
		return nil
	}

	route := &netlink.Route{
		LinkIndex: linkIndex,
		Scope:     netlink.SCOPE_LINK,
		Dst:       routeDst,
	}

	if err := netlink.RouteDel(route); err != nil {
		logger.Error("Failed to remove route for %s: %w", ip.String(), err)
		return err
	}

	logger.Info("Removed route for %s on link index %d", ip.String(), linkIndex)
	return nil
}
