package interfaces

import (
	"fmt"
	"net"
	"slices"

	"magitrickle/constant"
	"magitrickle/models"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func List(showAll bool) ([]models.InterfaceInfo, error) {
	networkInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	if !showAll {
		networkInterfaces = filterManaged(networkInterfaces)
	}

	friendlyNames, err := routerAPI.GetIfaceAliases()
	if err != nil {
		log.Debug().Err(err).Msg("failed to load interface aliases")
	}

	interfaces := make([]models.InterfaceInfo, 0, len(networkInterfaces))
	for _, iface := range networkInterfaces {
		interfaces = append(interfaces, models.InterfaceInfo{
			ID:   iface.Name,
			Name: friendlyNames[iface.Name],
			Kind: "interface",
		})
	}

	policies, err := routerAPI.GetInternetPolicies()
	if err != nil {
		log.Debug().Err(err).Msg("failed to load Internet access policies")
	} else {
		interfaces = append(interfaces, policies...)
	}

	return interfaces, nil
}

func filterManaged(interfaces []net.Interface) []net.Interface {
	filtered := make([]net.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		if slices.Contains(constant.IgnoredInterfaces, iface.Name) {
			continue
		}
		if iface.Flags&net.FlagPointToPoint == 0 && !hasDefaultRoute(iface.Name) {
			continue
		}
		filtered = append(filtered, iface)
	}

	return filtered
}

func hasDefaultRoute(ifaceName string) bool {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return false
	}

	for _, family := range []int{nl.FAMILY_V4, nl.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			LinkIndex: iface.Attrs().Index,
		}, netlink.RT_FILTER_OIF)
		if err != nil {
			log.Debug().Err(err).Str("interface", ifaceName).Msg("failed to inspect interface routes")
			continue
		}
		for _, route := range routes {
			if route.Dst == nil {
				if route.Gw != nil || route.LinkIndex == iface.Attrs().Index {
					return true
				}
				continue
			}
			ones, bits := route.Dst.Mask.Size()
			if ones == 0 && (bits == 32 || bits == 128) && (route.Gw != nil || route.LinkIndex == iface.Attrs().Index) {
				return true
			}
		}
	}
	return false
}
