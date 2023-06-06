package routemgr

import (
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

type RouteMgr struct {
	lock sync.Mutex
	set  bool

	gwRoute        *netlink.Route
	gwRouteNew     *netlink.Route
	gwRouteReplace *netlink.Route

	localRoutes []*netlink.Route
}

func NewRouteMgr() *RouteMgr {
	return &RouteMgr{}
}

const (
	ROUTE_MGR_ERR_NONE = iota
	ROUTE_MGR_ERR_NO_GW_ROUTE
	ROUTE_MGR_ERR_MULTI_GW_ROUTE
)

type RouteMgrError struct {
	reason int
}

func (e *RouteMgrError) Error() string {
	switch e.reason {
	case ROUTE_MGR_ERR_NO_GW_ROUTE:
		return "no gateway route"
	case ROUTE_MGR_ERR_MULTI_GW_ROUTE:
		return "multiple gateway route"
	default:
		return "unknown error"
	}
}

func (m *RouteMgr) Set(
	ifname net.Interface,
	clinet net.IP,
	server net.IP,
	local_cidrs []*net.IPNet) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.set {
		m.resetInner()
	}

	handle, err := netlink.NewHandle(syscall.AF_INET)
	if err != nil {
		return err
	}
	defer handle.Delete()

	link, err := handle.LinkByName(ifname.Name)
	if err != nil {
		return err
	}

	routes, err := handle.RouteList(link, syscall.AF_INET)
	if err != nil {
		return err
	}

	var gwRoute *netlink.Route
	for _, route := range routes {
		if route.Dst == nil {
			if gwRoute != nil {
				return &RouteMgrError{ROUTE_MGR_ERR_MULTI_GW_ROUTE}
			}
			gwRoute = &route
		}
	}

	if gwRoute == nil {
		return &RouteMgrError{ROUTE_MGR_ERR_NO_GW_ROUTE}
	}

	m.gwRoute = gwRoute
	m.gwRouteReplace = &netlink.Route{
		LinkIndex:  gwRoute.LinkIndex,
		ILinkIndex: gwRoute.ILinkIndex,
		Scope:      gwRoute.Scope,
		Dst:        gwRoute.Dst,
		Gw:         gwRoute.Gw,
		Priority:   gwRoute.Priority + 10,
	}
	m.gwRouteNew = &netlink.Route{
		LinkIndex:  gwRoute.LinkIndex,
		ILinkIndex: gwRoute.ILinkIndex,
		Scope:      gwRoute.Scope,
		Dst:        nil,
		Gw:         server,
		Priority:   gwRoute.Priority,
	}

	m.localRoutes = make([]*netlink.Route, 0, len(local_cidrs))
	for _, cidr := range local_cidrs {
		m.localRoutes = append(m.localRoutes, &netlink.Route{
			LinkIndex:  gwRoute.LinkIndex,
			ILinkIndex: gwRoute.ILinkIndex,
			Scope:      gwRoute.Scope,
			Dst:        cidr,
			Gw:         clinet,
			Priority:   gwRoute.Priority,
		})
	}

	err = handle.RouteDel(gwRoute)
	if err != nil {
		return err
	}
	err = handle.RouteAdd(m.gwRouteReplace)
	if err != nil {
		handle.RouteAdd(gwRoute)
		return err
	}
	err = handle.RouteAdd(m.gwRouteNew)
	if err != nil {
		handle.RouteDel(m.gwRouteReplace)
		handle.RouteAdd(gwRoute)
		return err
	}
	for i, route := range m.localRoutes {
		err = handle.RouteAdd(route)
		if err != nil {
			for j := 0; j < i; j++ {
				handle.RouteDel(m.localRoutes[j])
			}
			handle.RouteDel(m.gwRouteNew)
			handle.RouteDel(m.gwRouteReplace)
			handle.RouteAdd(gwRoute)
			return err
		}
	}

	return nil
}

func (m *RouteMgr) resetInner() {
	if !m.set {
		return
	}

	handle, err := netlink.NewHandle(syscall.AF_INET)
	if err != nil {
		return
	}
	defer handle.Delete()

	handle.RouteDel(m.gwRouteNew)
	handle.RouteDel(m.gwRouteReplace)
	for _, route := range m.localRoutes {
		handle.RouteDel(route)
	}
	handle.RouteAdd(m.gwRoute)

	m.set = false
}

func (m *RouteMgr) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.resetInner()
}
