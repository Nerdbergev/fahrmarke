package arplib

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime"
	"strings"
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
	hash := salt + strings.ToUpper(mac.String())
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

	timeout := 3 * time.Second

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.New("Failed to get interface: " + err.Error())
	}

	ips, err := hostsFromCIDR(cidr)
	if err != nil {
		return nil, errors.New("Failed to get hosts from CIDR: " + err.Error())
	}

	log.Printf("Starting ARP scan for %d IPs on interface %s", len(ips), interfaceName)

	// open ARP client on the interface (requires elevated privileges)
	c, err := arp.Dial(iface)
	if err != nil {
		return nil, errors.New("Failed to open ARP client: " + err.Error())
	}
	defer c.Close()

	// Use buffered channel to prevent goroutines from blocking
	results := make(chan net.HardwareAddr, len(ips))
	var wg sync.WaitGroup

	// Process IPs in batches to avoid overwhelming the network
	batchSize := 20
	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}

		for j := i; j < end; j++ {
			ip := ips[j]
			wg.Add(1)
			go func(ip netip.Addr) {
				defer wg.Done()

				// Create a separate client for each goroutine to avoid deadline interference
				localClient, err := arp.Dial(iface)
				if err != nil {
					log.Printf("Failed to create ARP client for %s: %v", ip, err)
					return
				}
				defer localClient.Close()

				// Set deadline for this specific request
				err = localClient.SetReadDeadline(time.Now().Add(timeout))
				if err != nil {
					log.Printf("Failed to set read deadline for %s: %v", ip, err)
					return
				}

				mac, err := localClient.Resolve(ip)
				if err != nil {
					return
				}

				if mac != nil {
					results <- mac
				}
			}(ip)
		}

		// Wait a bit between batches to avoid overwhelming the network
		if end < len(ips) {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Wait for all goroutines to complete with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(results)
		done <- true
	}()

	var found []net.HardwareAddr
	scanTimeout := time.After(timeout * 3) // Give more time for all requests

	// Collect results until all goroutines are done or timeout
	collecting := true
	for collecting {
		select {
		case mac, ok := <-results:
			if !ok {
				// Channel closed, all goroutines done
				collecting = false
			} else if mac != nil {
				found = append(found, mac)
			}
		case <-done:
			// All goroutines finished
			collecting = false
		case <-scanTimeout:
			collecting = false
		}
	}

	// Drain any remaining results from the channel if it's still open
	select {
	case <-done:
		// Goroutines finished, channel is closed, drain it
		for mac := range results {
			if mac != nil {
				found = append(found, mac)
			}
		}
	default:
		// Timeout occurred, channel might still be open
	}

	log.Printf("ARP scan completed: found %d devices", len(found))
	return found, nil
}

func performMacScan(interfaceName string, cidr string) {
	log.Printf("Starting MAC scan on interface %s with CIDR %s", interfaceName, cidr)
	macs, err := Scan(interfaceName, cidr)
	if err != nil {
		log.Println("Error during periodic scan:", err)
		return
	}

	devices, err := db.GetDevicesSparse()
	if err != nil {
		log.Println("Error retrieving devices from database:", err)
		return
	}

	// Build a map for O(1) lookup instead of O(n) for each MAC
	deviceMap := make(map[string]int) // hashed MAC -> user ID
	for _, device := range devices {
		deviceMap[device.MACAddress] = device.UserID
	}

	// Track unique online user IDs
	onlineUserSet := make(map[int]bool)
	for _, mac := range macs {
		// Check each device's salt to see if it matches
		for _, device := range devices {
			hashedMac := HashMAC(mac, device.Salt)
			if userID, found := deviceMap[hashedMac]; found {
				onlineUserSet[userID] = true
				break // Found a match, no need to check other devices for this MAC
			}
		}
	}

	onlineMap.Clear()
	for uid := range onlineUserSet {
		onlineMap.Add(uid)
	}
	log.Printf("Scan complete: %d users are now marked as online", len(onlineUserSet))
}

func StartScanTicker(interfaceName string, cidr string, scanInterval time.Duration) {
	performMacScan(interfaceName, cidr)
	ticker := time.NewTicker(scanInterval)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			performMacScan(interfaceName, cidr)
		}
	}()
}

func CheckUserIsPresent(UserID int) bool {
	return onlineMap.IsUserOnline(UserID)
}
