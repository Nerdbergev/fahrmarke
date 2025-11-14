package arplib

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	db "github.com/Nerdberg/fahrmarke/dblib"
	"github.com/mdlayher/arp"
)

const hashIterations = 1000

type scanResults struct {
	sync.RWMutex
	usersOnline map[int]bool
}

var onlineMap scanResults = scanResults{
	usersOnline: make(map[int]bool),
}

func (s *scanResults) Add(userID int) {
	s.Lock()
	defer s.Unlock()
	s.usersOnline[userID] = true
}

func (s *scanResults) Clear() {
	s.Lock()
	defer s.Unlock()
	s.usersOnline = make(map[int]bool)
}

func (s *scanResults) IsUserOnline(userID int) bool {
	s.RLock()
	defer s.RUnlock()
	return s.usersOnline[userID]
}

func HashMAC(mac net.HardwareAddr, salt string) string {
	hash := salt + mac.String()
	for i := 0; i < hashIterations; i++ {
		hasher := sha256.New()
		hasher.Write([]byte(hash))
		hash = hex.EncodeToString(hasher.Sum(nil))
	}
	return hash
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
	devices, err := db.GetDevicesSparse()
	if err != nil {
		log.Println("Error retrieving devices from database:", err)
		return
	}
	var onlineUserIDs []int
	for _, mac := range macs {
		for i, device := range devices {
			hashedMac := HashMAC(mac, device.Salt)
			if hashedMac == device.MACAddress {
				onlineUserIDs = append(onlineUserIDs, device.UserID)
				// Remove matched device to speed up further lookups
				devices = append(devices[:i], devices[i+1:]...)
				break
			}
		}
	}
	onlineMap.Clear()
	for _, uid := range onlineUserIDs {
		onlineMap.Add(uid)
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

func CheckUserIsPresent(UserID int) bool {
	return onlineMap.IsUserOnline(UserID)
}
