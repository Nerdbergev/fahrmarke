package arplib

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/mdlayher/arp"
)

var results arpResults

type arpResults struct {
	Results []net.HardwareAddr
	mu      sync.Mutex
}

func (r *arpResults) Add(mac net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Results = append(r.Results, mac)
}

func (r *arpResults) Get() []net.HardwareAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Results
}

func (r *arpResults) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Results = []net.HardwareAddr{}
}

func hostsFromCIDR(cidr string) ([]netip.Addr, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		// skip network and broadcast
		nip, _ := netip.AddrFromSlice(ip)

		ips = append(ips, nip)
	}
	// remove first (network) and last (broadcast) if applicable
	if len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func Scan(interfaceName string, cidr string) ([]net.HardwareAddr, error) {
	//As ARP is not implemented on windows by mdlayher/arp, we skip scanning on windows
	if runtime.GOOS == "windows" {
		log.Println("Skipping ARP scan on Windows")
		dummy := []net.HardwareAddr{}
		dummystring := []string{"de:ad:be:ef:de:ad", "ab:cd:ef:01:23:45"}
		for _, ds := range dummystring {
			mac, err := net.ParseMAC(ds)
			if err == nil {
				dummy = append(dummy, mac)
			}
		}
		return dummy, nil
	}

	timeout := 500 * time.Millisecond

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.New("Failed to get interface: " + err.Error())
	}

	ips, err := hostsFromCIDR(cidr)
	if err != nil {
		return nil, errors.New("Failed to get hosts from CIDR: " + err.Error())
	}

	// open ARP client on the interface (requires elevated privileges)
	c, err := arp.Dial(iface)
	if err != nil {
		return nil, errors.New("Failed to open ARP client: " + err.Error())
	}
	defer c.Close()

	results := make(chan net.HardwareAddr)

	for _, ip := range ips {
		go func(ip netip.Addr) {
			// set deadline per request to avoid blocking forever
			_ = c.SetReadDeadline(time.Now().Add(timeout))
			mac, err := c.Resolve(ip)
			if err == nil && mac != nil {
				results <- mac
				return
			}
			// if Resolve failed, optionally try sending a request manually
			// (c.Resolve already does ARP request + wait)
			results <- nil
		}(ip)
	}

	// collect responses with a simple timeout
	deadline := time.After(time.Duration(len(ips))*(timeout) + 2*time.Second)
	var found []net.HardwareAddr
expect:
	for i := 0; i < len(ips); i++ {
		select {
		case r := <-results:
			if r != nil {
				found = append(found, r)
			}
		case <-deadline:
			break expect
		}
	}
	return found, nil
}

func performMacScan(interfaceName string, cidr string) {
	macs, err := Scan(interfaceName, cidr)
	if err != nil {
		log.Println("Error during periodic scan:", err)
	}
	results.Clear()
	for _, mac := range macs {
		results.Add(mac)
	}
}

func StartScanTicker(interfaceName string, cidr string, scanInterval time.Duration) {
	performMacScan(interfaceName, cidr)
	ticker := time.NewTicker(scanInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				performMacScan(interfaceName, cidr)
			}
		}
	}()
}

func GetScanResults() []net.HardwareAddr {
	return results.Get()
}

func CheckMACisOnline(mac net.HardwareAddr) bool {
	macs := results.Get()
	for _, m := range macs {
		if m.String() == mac.String() {
			return true
		}
	}
	return false
}
