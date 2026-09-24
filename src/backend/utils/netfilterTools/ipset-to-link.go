package netfilterTools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const Blackhole = "blackhole"

const (
	failoverProbeTimeout           = time.Second
	failoverFailureLimit           = 3
	failoverRecoveryLimit          = 2
	failoverUnhealthyRoutePriority = 65000
)

var failoverProbeEndpoints = []struct {
	network  string
	endpoint string
}{
	{network: "tcp4", endpoint: "1.1.1.1:443"},
	{network: "tcp4", endpoint: "8.8.8.8:443"},
	{network: "tcp6", endpoint: "[2606:4700:4700::1111]:443"},
	{network: "tcp6", endpoint: "[2001:4860:4860::8888]:443"},
}

type IPSetToLink struct {
	enabled atomic.Bool
	locker  sync.Mutex

	chainName          string
	ifaceName          string
	fallbackIfaceNames []string
	startIdx           uint32
	ipset              *IPSet
	nh                 *Helper
	mark               uint32
	table              int
	policyTable4       int
	policyTable6       int
	usePolicy          bool
	ip4Rule            *netlink.Rule
	ip6Rule            *netlink.Rule
	ip4Route           *netlink.Route
	ip6Route           *netlink.Route
	ifaceRoutes        map[string]*interfaceRoute
}

type interfaceRoute struct {
	ipv4        *netlink.Route
	ipv6        *netlink.Route
	linkUp      bool
	healthKnown bool
	healthy     bool
	failures    int
	successes   int
}

func (r *IPSetToLink) insertIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}

	ipsetName := r.ipset.ipsetName
	if ipt.Proto() == iptables.ProtocolIPv4 {
		ipsetName += "_4"
	} else {
		ipsetName += "_6"
	}

	var err error
	if !r.usePolicy {
		/*
			Filter Forward
		*/
		err := ipt.RegisterChainOverride("filter", r.chainName)
		if err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}

		for _, ifaceName := range r.routeInterfaces() {
			err = ipt.Append("filter", r.chainName, "-o", ifaceName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "ACCEPT")
			if err != nil {
				return fmt.Errorf("failed to allow forwarding through interface %s: %w", ifaceName, err)
			}
		}

		err = ipt.Append("filter", "FORWARD", "-j", r.chainName)
		if err != nil {
			return fmt.Errorf("failed to append rule to FORWARD: %w", err)
		}
	}

	/*
		Mangle Prerouting
	*/

	err = ipt.RegisterChainOverride("mangle", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	markStr := strconv.Itoa(int(r.mark))
	for _, iptablesArgs := range [][]string{
		{"-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"},
		{"-m", "set", "--match-set", ipsetName, "dst", "-j", "MARK", "--set-mark", markStr},
		{"-m", "set", "--match-set", ipsetName, "dst", "-j", "CONNMARK", "--save-mark"}, // Without this rule, routing on Keenetic routers did not work; DO NOT REMOVE!
	} {
		err = ipt.Append("mangle", r.chainName, iptablesArgs...)
		if err != nil {
			return fmt.Errorf("failed to append rule: %w", err)
		}
	}

	err = ipt.Append("mangle", "PREROUTING", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
	}

	/*
		NAT Postrouting
	*/

	err = ipt.RegisterChainOverride("nat", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	err = ipt.Append("nat", r.chainName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	err = ipt.Append("nat", "POSTROUTING", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
	}

	err = ipt.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

func (r *IPSetToLink) deleteIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	var errs []error
	var err error

	/*
		Filter Forward
	*/

	if !r.usePolicy {
		err := ipt.RegisterChainDelete("filter", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to clear chain: %w", err))
		}

		err = ipt.Delete("filter", "FORWARD", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlink chain: %w", err))
		}
	}

	/*
		Mangle Prerouting
	*/

	err = ipt.RegisterChainDelete("mangle", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = ipt.Delete("mangle", "PREROUTING", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	/*
		NAT Postrouting
	*/

	err = ipt.RegisterChainDelete("nat", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = ipt.Delete("nat", "POSTROUTING", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = ipt.Commit()
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
	}
	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRule() error {
	if r.nh.IPTables4 != nil {
		table := r.table
		if r.usePolicy {
			table = r.policyTable4
		}
		if table == 0 {
			return fmt.Errorf("IPv4 route table is unavailable")
		}
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = table
		rule.Family = nl.FAMILY_V4
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip4Rule = rule
	}

	if r.nh.IPTables6 != nil {
		table := r.table
		if r.usePolicy {
			table = r.policyTable6
		}
		if table == 0 {
			return fmt.Errorf("IPv6 route table is unavailable")
		}
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = table
		rule.Family = nl.FAMILY_V6
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip6Rule = rule
	}

	return nil
}

func (r *IPSetToLink) deleteIPRule() error {
	var errs []error

	if r.ip4Rule != nil {
		err := netlink.RuleDel(r.ip4Rule)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip4Rule = nil
	}

	if r.ip6Rule != nil {
		err := netlink.RuleDel(r.ip6Rule)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip6Rule = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRoute() error {
	if r.usePolicy {
		return nil
	}
	r.ifaceRoutes = make(map[string]*interfaceRoute)

	if r.nh.IPTables4 != nil {
		route := &netlink.Route{
			Priority: 65535,
			Dst:      &net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}},
			Table:    r.table,
			Type:     unix.RTN_BLACKHOLE,
			Family:   nl.FAMILY_V4,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding ipv4 blackhole route: %w", err)
		}
		r.ip4Route = route
	}

	if r.nh.IPTables6 != nil {
		route := &netlink.Route{
			Priority: 65535,
			Dst:      &net.IPNet{IP: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			Table:    r.table,
			Type:     unix.RTN_BLACKHOLE,
			Family:   nl.FAMILY_V6,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding ipv6 blackhole route: %w", err)
		}
		r.ip6Route = route
	}

	if r.ifaceName == Blackhole {
		return nil
	}

	var errs []error
	for index, ifaceName := range r.routeInterfaces() {
		state := &interfaceRoute{linkUp: false, healthy: false}
		r.ifaceRoutes[ifaceName] = state
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			if errors.As(err, &netlink.LinkNotFoundError{}) {
				log.Warn().Str("iface", ifaceName).Msg("interface not found, waiting for it to appear")
				continue
			}
			errs = append(errs, fmt.Errorf("error while getting interface %s: %w", ifaceName, err))
			continue
		}
		state.linkUp = linkIsOperational(iface)
		state.healthy = state.linkUp
		if !state.linkUp {
			log.Warn().Str("iface", ifaceName).Msg("interface is down")
			continue
		}
		errs = append(errs, r.refreshIfaceRoute(ifaceName, iface, index)...)
	}
	return errors.Join(errs...)
}

func (r *IPSetToLink) routeInterfaces() []string {
	if r.ifaceName == "" || r.ifaceName == Blackhole {
		return nil
	}
	interfaces := make([]string, 0, 1+len(r.fallbackIfaceNames))
	interfaces = append(interfaces, r.ifaceName)
	seen := map[string]struct{}{r.ifaceName: {}}
	for _, iface := range r.fallbackIfaceNames {
		if iface == "" || iface == Blackhole {
			continue
		}
		if _, exists := seen[iface]; exists {
			continue
		}
		seen[iface] = struct{}{}
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

func (r *IPSetToLink) refreshIfaceRoute(ifaceName string, iface netlink.Link, index int) []error {
	state := r.ifaceRoutes[ifaceName]
	if state == nil || !state.linkUp || !linkIsOperational(iface) {
		return nil
	}
	priority := 10 + index*10
	if state.healthKnown && !state.healthy {
		priority = failoverUnhealthyRoutePriority + index
	}
	var errs []error
	var err error
	if r.nh.IPTables4 != nil {
		state.ipv4, err = r.updateIfaceRoute(iface, nl.FAMILY_V4, state.ipv4, ifaceName, priority)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if r.nh.IPTables6 != nil {
		state.ipv6, err = r.updateIfaceRoute(iface, nl.FAMILY_V6, state.ipv6, ifaceName, priority)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func linkIsOperational(iface netlink.Link) bool {
	attrs := iface.Attrs()
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}
	return attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown
}

func (r *IPSetToLink) updateIfaceRoute(iface netlink.Link, family int, current *netlink.Route, ifaceName string, priority int) (*netlink.Route, error) {
	ipLen := net.IPv4len
	if family == nl.FAMILY_V6 {
		ipLen = net.IPv6len
	}

	route := &netlink.Route{
		Priority:  priority,
		LinkIndex: iface.Attrs().Index,
		Table:     r.table,
		Family:    family,
		Dst:       &net.IPNet{IP: make(net.IP, ipLen), Mask: make(net.IPMask, ipLen)},
	}

	if iface.Attrs().Flags&net.FlagPointToPoint == 0 {
		gateway, err := getGwFromIface(iface, family)
		if err != nil {
			log.Debug().Str("iface", ifaceName).Err(err).Int("family", family).Msg("default gateway not found; skipping interface route")
			if current != nil {
				if deleteErr := netlink.RouteDel(current); deleteErr != nil && !errors.Is(deleteErr, unix.ESRCH) {
					return current, fmt.Errorf("error deleting stale iface route: %w", deleteErr)
				}
			}
			return nil, nil
		}
		route.Gw = gateway
	}

	if current != nil {
		if route.Gw.Equal(current.Gw) &&
			route.LinkIndex == current.LinkIndex &&
			route.Priority == current.Priority &&
			route.Table == current.Table {
			return current, nil
		}
		if err := netlink.RouteDel(current); err != nil && !errors.Is(err, unix.ESRCH) {
			return current, fmt.Errorf("error deleting iface route: %w", err)
		}
	}

	if err := netlink.RouteAdd(route); err != nil {
		if errors.Is(err, unix.ENODEV) {
			log.Warn().Str("iface", ifaceName).Int("family", family).Msg("interface not ready for this IP family, skipping route")
			return nil, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("error adding iface route: %w", err)
		}
	}
	return route, nil
}

func getGwFromIface(iface netlink.Link, family int) (net.IP, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		LinkIndex: iface.Attrs().Index,
	}, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		isDefault := route.Dst == nil
		if route.Dst != nil {
			ones, bits := route.Dst.Mask.Size()
			isDefault = ones == 0 && bits == ipFamilyBits(family)
		}
		if isDefault && route.LinkIndex == iface.Attrs().Index {
			return route.Gw, nil
		}
	}
	return nil, fmt.Errorf("no gateway found for interface %s", iface.Attrs().Name)
}

func ipFamilyBits(family int) int {
	if family == nl.FAMILY_V6 {
		return net.IPv6len * 8
	}
	return net.IPv4len * 8
}

func (r *IPSetToLink) deleteIPRoute() error {
	var errs []error
	deleteRoute := func(route *netlink.Route) {
		if route == nil {
			return
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
	}
	for _, state := range r.ifaceRoutes {
		deleteRoute(state.ipv4)
		deleteRoute(state.ipv6)
	}
	r.ifaceRoutes = nil
	deleteRoute(r.ip4Route)
	deleteRoute(r.ip6Route)
	r.ip4Route, r.ip6Route = nil, nil
	return errors.Join(errs...)
}

func (r *IPSetToLink) getUnusedMarkAndTable() (idx uint32, err error) {
	// Find unused mark and table
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return 0, fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for idx = r.startIdx; idx < 0x7ffffffe; idx++ {
		_, tableExists := tableMap[int(idx)]
		_, markExists := markMap[idx]
		if !tableExists && !markExists {
			break
		}
	}

	return idx, nil
}

func (r *IPSetToLink) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	var err error
	idx, err := r.getUnusedMarkAndTable()
	if err != nil {
		return err
	}
	r.mark, r.table = idx, int(idx)

	err = r.insertIPRule()
	if err != nil {
		return err
	}

	err = r.insertIPRoute()
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables4)
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables6)
	if err != nil {
		return err
	}

	return nil
}

func (r *IPSetToLink) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	err := r.enable()
	if err != nil {
		r.disable()
	} else {
		log.Debug().
			Int("table", r.table).
			Int("mark", int(r.mark)).
			Msg("using ip table and mark")
	}

	return err
}

func (r *IPSetToLink) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

func (r *IPSetToLink) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	return r.disable()
}

func (r *IPSetToLink) ClearIfDisabled() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if r.enabled.Load() {
		return nil
	}

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

func (r *IPSetToLink) LinkUpHook(event netlink.LinkUpdate) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() || r.usePolicy {
		return nil
	}
	ifaceName := event.Link.Attrs().Name
	state := r.ifaceRoutes[ifaceName]
	if state == nil {
		return nil
	}

	state.linkUp = false
	if event.Header.Type == unix.RTM_NEWLINK {
		state.linkUp = linkIsOperational(event.Link)
	}
	if !state.linkUp {
		return r.deleteInterfaceRoutes(state)
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("error while getting interface %s: %w", ifaceName, err)
	}
	index := slices.Index(r.routeInterfaces(), ifaceName)
	if index < 0 {
		return nil
	}
	return errors.Join(r.refreshIfaceRoute(ifaceName, iface, index)...)
}

func (r *IPSetToLink) deleteInterfaceRoutes(state *interfaceRoute) error {
	var errs []error
	for _, route := range []*netlink.Route{state.ipv4, state.ipv6} {
		if route == nil {
			continue
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, err)
		}
	}
	state.ipv4, state.ipv6 = nil, nil
	return errors.Join(errs...)
}

func (r *IPSetToLink) CheckHealth(ctx context.Context) error {
	if r.usePolicy || len(r.routeInterfaces()) <= 1 {
		return nil
	}

	r.locker.Lock()
	if !r.enabled.Load() {
		r.locker.Unlock()
		return nil
	}
	interfaces := r.routeInterfaces()
	var errs []error
	for index, ifaceName := range interfaces {
		state := r.ifaceRoutes[ifaceName]
		if state == nil {
			continue
		}
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			state.linkUp = false
			if !errors.As(err, &netlink.LinkNotFoundError{}) {
				errs = append(errs, fmt.Errorf("error while getting interface %s: %w", ifaceName, err))
			}
			errs = append(errs, r.deleteInterfaceRoutes(state))
			continue
		}
		state.linkUp = linkIsOperational(iface)
		if !state.linkUp {
			errs = append(errs, r.deleteInterfaceRoutes(state))
			continue
		}
		errs = append(errs, r.refreshIfaceRoute(ifaceName, iface, index)...)
	}
	r.locker.Unlock()

	type result struct {
		iface string
		up    bool
	}
	results := make(chan result, len(interfaces))
	for _, iface := range interfaces {
		go func(iface string) {
			results <- result{iface: iface, up: probeInterface(ctx, iface, r.mark)}
		}(iface)
	}
	probeResults := make(map[string]bool, len(interfaces))
	for range interfaces {
		select {
		case result := <-results:
			probeResults[result.iface] = result.up
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	r.locker.Lock()
	defer r.locker.Unlock()
	if !r.enabled.Load() {
		return nil
	}

	for index, ifaceName := range interfaces {
		state := r.ifaceRoutes[ifaceName]
		if state == nil {
			continue
		}
		if probeResults[ifaceName] {
			state.failures = 0
			state.successes++
			if !state.healthKnown || (!state.healthy && state.successes >= failoverRecoveryLimit) {
				wasUnhealthy := state.healthKnown && !state.healthy
				state.healthKnown = true
				state.healthy = true
				if wasUnhealthy {
					log.Info().Str("interface", ifaceName).Msg("internet connectivity restored; restoring route priority")
				}
				if state.linkUp {
					iface, err := netlink.LinkByName(ifaceName)
					if err != nil {
						errs = append(errs, fmt.Errorf("error while getting interface %s: %w", ifaceName, err))
					} else {
						errs = append(errs, r.refreshIfaceRoute(ifaceName, iface, index)...)
					}
				}
			}
			continue
		}

		state.successes = 0
		state.failures++
		if state.failures >= failoverFailureLimit && (!state.healthKnown || state.healthy) {
			state.healthKnown = true
			state.healthy = false
			if state.linkUp {
				iface, err := netlink.LinkByName(ifaceName)
				if err != nil {
					errs = append(errs, fmt.Errorf("error while getting interface %s: %w", ifaceName, err))
				} else {
					errs = append(errs, r.refreshIfaceRoute(ifaceName, iface, index)...)
				}
			}
			log.Warn().Str("interface", ifaceName).Msg("internet connectivity check failed; moving this route behind configured fallbacks")
		}
	}
	return errors.Join(errs...)
}

func probeInterface(ctx context.Context, ifaceName string, mark uint32) bool {
	probeCtx, cancel := context.WithTimeout(ctx, failoverProbeTimeout)
	defer cancel()

	results := make(chan bool, len(failoverProbeEndpoints))
	for _, endpoint := range failoverProbeEndpoints {
		go func(probe struct {
			network  string
			endpoint string
		}) {
			dialer := net.Dialer{
				Timeout: failoverProbeTimeout,
				Control: func(_, _ string, rawConn syscall.RawConn) error {
					var socketErr error
					if err := rawConn.Control(func(fd uintptr) {
						if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
							socketErr = err
							return
						}
						socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
					}); err != nil {
						return err
					}
					return socketErr
				},
			}
			conn, err := dialer.DialContext(probeCtx, probe.network, probe.endpoint)
			if err == nil {
				_ = conn.Close()
			}
			results <- err == nil
		}(endpoint)
	}

	for range failoverProbeEndpoints {
		select {
		case ok := <-results:
			if ok {
				return true
			}
		case <-probeCtx.Done():
			return false
		}
	}
	return false
}

func (r *IPSetToLink) AddrChangeHook(event netlink.AddrUpdate) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() || r.usePolicy || r.ifaceName == Blackhole {
		return nil
	}

	for index, ifaceName := range r.routeInterfaces() {
		state := r.ifaceRoutes[ifaceName]
		if state == nil || !state.linkUp {
			continue
		}
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("error while getting interface %s: %w", ifaceName, err)
		}
		if iface.Attrs().Index != event.LinkIndex {
			continue
		}
		return errors.Join(r.refreshIfaceRoute(ifaceName, iface, index)...)
	}
	return nil
}

func (nh *Helper) IPSetToLink(name string, ifaceName string, ipset *IPSet) *IPSetToLink {
	return &IPSetToLink{
		nh:        nh,
		chainName: nh.ChainPrefix + name,
		ifaceName: ifaceName,
		ipset:     ipset,
		startIdx:  nh.StartIdx,
	}
}

func (nh *Helper) IPSetToLinkWithFallback(name, ifaceName string, fallbackIfaceNames []string, ipset *IPSet) *IPSetToLink {
	r := nh.IPSetToLink(name, ifaceName, ipset)
	r.fallbackIfaceNames = append([]string(nil), fallbackIfaceNames...)
	return r
}

func (nh *Helper) IPSetToPolicy(name string, table4, table6 int, ipset *IPSet) *IPSetToLink {
	return &IPSetToLink{
		nh:           nh,
		chainName:    nh.ChainPrefix + name,
		ifaceName:    "",
		ipset:        ipset,
		startIdx:     nh.StartIdx,
		policyTable4: table4,
		policyTable6: table6,
		usePolicy:    true,
	}
}
