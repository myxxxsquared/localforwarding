package routemgr

import (
	"net"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type RouteMgr struct {
	lock         sync.Mutex
	set          bool
	shuttingdown bool

	gwRoute        *netlink.Route
	gwRouteNew     *netlink.Route
	gwRouteReplace *netlink.Route

	localRoutes []*netlink.Route
}

func NewRouteMgr() *RouteMgr {
	return &RouteMgr{}
}

func (m *RouteMgr) Shutdown() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.shuttingdown = true
	m.resetInner()
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

	if m.shuttingdown {
		return nil
	}

	log.WithFields(log.Fields{
		"client": clinet,
		"server": server,
		"ifname": ifname.Name,
	}).Info("Setting route")

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

	log.WithFields(log.Fields{
		"routes": routes,
	}).Info("Route list")

	var gwRoute netlink.Route
	var hasGwRoute bool

	for _, route := range routes {
		if route.Dst == nil && route.Gw != nil {
			if hasGwRoute {
				return &RouteMgrError{ROUTE_MGR_ERR_MULTI_GW_ROUTE}
			}
			gwRoute = route
			hasGwRoute = true
		}
	}

	if !hasGwRoute {
		return &RouteMgrError{ROUTE_MGR_ERR_NO_GW_ROUTE}
	}

	log.WithField("route", gwRoute).Info("Found gateway route")

	m.gwRoute = &gwRoute
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
			Gw:         gwRoute.Gw,
			Priority:   gwRoute.Priority,
		})
	}

	err = handle.RouteDel(&gwRoute)
	if err != nil {
		return err
	}
	log.WithField("route", gwRoute).Info("Deleted gateway route")

	err = handle.RouteAdd(m.gwRouteReplace)
	if err != nil {
		handle.RouteAdd(&gwRoute)
		return err
	}
	log.WithField("route", m.gwRouteReplace).Info("Added gateway route with higher priority")

	err = handle.RouteAdd(m.gwRouteNew)
	if err != nil {
		handle.RouteDel(m.gwRouteReplace)
		handle.RouteAdd(&gwRoute)
		return err
	}
	log.WithField("route", m.gwRouteNew).Info("Added gateway route")

	for i, route := range m.localRoutes {
		err = handle.RouteAdd(route)
		if err != nil && err.Error() != "file exists" {
			for j := 0; j < i; j++ {
				handle.RouteDel(m.localRoutes[j])
			}
			handle.RouteDel(m.gwRouteNew)
			handle.RouteDel(m.gwRouteReplace)
			handle.RouteAdd(&gwRoute)
			return err
		}
		log.WithField("route", route).Info("Added local route")
	}

	m.set = true

	return nil
}

func (m *RouteMgr) resetInner() {
	if !m.set {
		return
	}

	handle, err := netlink.NewHandle(syscall.AF_INET)
	if err != nil {
		log.WithError(err).Error("Error creating handle when reset route")
		return
	}
	defer handle.Delete()

	log.Info("Resetting route")

	for _, route := range m.localRoutes {
		err := handle.RouteDel(route)
		if err != nil {
			log.WithError(err).Error("Error deleting local route")
		}
	}
	err = handle.RouteDel(m.gwRouteNew)
	if err != nil {
		log.WithError(err).Error("Error deleting gateway route")
	}
	err = handle.RouteDel(m.gwRouteReplace)
	if err != nil {
		log.WithError(err).Error("Error deleting gateway route")
	}
	err = handle.RouteAdd(m.gwRoute)
	if err != nil {
		log.WithError(err).Error("Error adding gateway route")
	}

	m.set = false
}

func (m *RouteMgr) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.resetInner()
}
