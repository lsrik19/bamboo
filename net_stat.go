// Package main implements 100-dimensional damped network feature extraction.
//
// Theoretical Foundation:
//   - Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018.
//   - Tracks 5 multi-scale temporal windows (decay lambdas 5.0, 3.0, 1.0, 0.1, 0.01) across 5 traffic contexts:
//     MAC-IP (1D), Source IP (1D), Jitter (1D), Source Socket (1D), and Host/Socket Pairs (2D covariance).
package main

var Lambdas = []float64{5.0, 3.0, 1.0, 0.1, 0.01}

type MacIPKey struct {
	Mac string
	IP  string
}

type HostPairKey struct {
	HostA string
	HostB string
}

type JitterKey struct {
	SrcIP string
	DstIP string
}

type SocketKey struct {
	IP   string
	Port string
}

type SocketPairKey struct {
	SockA SocketKey
	SockB SocketKey
}

// NetStat tracks incremental statistics across all network contexts
// Matches the original Bamboo netStat.py structure:
//
//	MIstat (MAC-IP 1D) + HHstat (Host-Host 1D+2D) + HHjit (Jitter 1D) + HpHpstat (Socket 1D+2D)
type NetStat struct {
	HT_MAC_IP  map[MacIPKey][]*IncStat
	HT_HH      map[HostPairKey][]*IncStatCov
	HT_SrcIP   map[string][]*IncStat
	HT_Jitter  map[JitterKey][]*IncStat
	LastTime   map[JitterKey]float64
	HT_HpHp    map[SocketPairKey][]*IncStatCov
	HT_SrcSock map[SocketKey][]*IncStat

	featureBuf []float64 // pre-allocated scratch buffer for feature extraction
}

func NewNetStat() *NetStat {
	return &NetStat{
		HT_MAC_IP:  make(map[MacIPKey][]*IncStat),
		HT_HH:      make(map[HostPairKey][]*IncStatCov),
		HT_SrcIP:   make(map[string][]*IncStat),
		HT_Jitter:  make(map[JitterKey][]*IncStat),
		LastTime:   make(map[JitterKey]float64),
		HT_HpHp:    make(map[SocketPairKey][]*IncStatCov),
		HT_SrcSock: make(map[SocketKey][]*IncStat),
		featureBuf: make([]float64, 0, 100),
	}
}

func canonicalHostPair(a, b string) (HostPairKey, int) {
	if a < b {
		return HostPairKey{HostA: a, HostB: b}, 0 // a is stream 0
	}
	return HostPairKey{HostA: b, HostB: a}, 1 // a is stream 1 (b came first alphabetically)
}

func canonicalSocketPair(a, b SocketKey) (SocketPairKey, int) {
	if a.IP < b.IP || (a.IP == b.IP && a.Port < b.Port) {
		return SocketPairKey{SockA: a, SockB: b}, 0
	}
	return SocketPairKey{SockA: b, SockB: a}, 1
}

func getOrCreate1D[K comparable](table map[K][]*IncStat, key K) []*IncStat {
	if stats, exists := table[key]; exists {
		return stats
	}
	stats := make([]*IncStat, len(Lambdas))
	for i, l := range Lambdas {
		stats[i] = NewIncStat(l)
	}
	table[key] = stats
	return stats
}

func getOrCreateCov[K comparable](table map[K][]*IncStatCov, key K) []*IncStatCov {
	if stats, exists := table[key]; exists {
		return stats
	}
	stats := make([]*IncStatCov, len(Lambdas))
	for i, l := range Lambdas {
		stats[i] = NewIncStatCov(l)
	}
	table[key] = stats
	return stats
}

// UpdateAndExtract updates statistics with the packet and returns the feature vector.
func (ns *NetStat) UpdateAndExtract(meta *PacketMetaData) []float64 {
	features := ns.featureBuf[:0] // reset length, reuse backing array

	x := float64(meta.Length)
	t := meta.Timestamp

	macIPKey := MacIPKey{Mac: meta.SrcMac, IP: meta.SrcIP}
	hhKey, hhStreamIdx := canonicalHostPair(meta.SrcIP, meta.DstIP)
	jitKey := JitterKey{SrcIP: meta.SrcIP, DstIP: meta.DstIP}

	srcSocket := SocketKey{IP: meta.SrcIP, Port: meta.SrcPort}
	dstSocket := SocketKey{IP: meta.DstIP, Port: meta.DstPort}

	// For ARP, use MAC addresses for socket-level stats (matching original)
	if meta.Protocol == "ARP" {
		srcSocket = SocketKey{IP: meta.SrcMac, Port: ""}
		dstSocket = SocketKey{IP: meta.DstMac, Port: ""}
	}

	hpKey, hpStreamIdx := canonicalSocketPair(srcSocket, dstSocket)

	macIPStats := getOrCreate1D(ns.HT_MAC_IP, macIPKey)
	srcIPStats := getOrCreate1D(ns.HT_SrcIP, meta.SrcIP)
	hhStats := getOrCreateCov(ns.HT_HH, hhKey)
	jitterStats := getOrCreate1D(ns.HT_Jitter, jitKey)
	hpStats := getOrCreateCov(ns.HT_HpHp, hpKey)
	srcSockStats := getOrCreate1D(ns.HT_SrcSock, srcSocket)

	// Jitter calculation
	_, hasLast := ns.LastTime[jitKey]
	dt := 0.0
	if hasLast {
		dt = t - ns.LastTime[jitKey]
		if dt < 0 {
			dt = 0
		}
	}
	ns.LastTime[jitKey] = t

	for i := range Lambdas {
		macIPStats[i].Update(x, t)
		srcIPStats[i].Update(x, t)
		hhStats[i].Update(hhStreamIdx, x, t)
		jitterStats[i].Update(dt, t)
		hpStats[i].Update(hpStreamIdx, x, t)
		srcSockStats[i].Update(x, t)

		miW, miMean, miVar := macIPStats[i].AllStats1D()
		features = append(features, miW, miMean, miVar)

		srcW, srcMean, srcVar := srcIPStats[i].AllStats1D()
		features = append(features, srcW, srcMean, srcVar)
		hhRadius, hhMag, hhCov, hhPCC := hhStats[i].Stats2D()
		features = append(features, hhRadius, hhMag, hhCov, hhPCC)

		jitW, jitMean, jitVar := jitterStats[i].AllStats1D()
		features = append(features, jitW, jitMean, jitVar)

		sockW, sockMean, sockVar := srcSockStats[i].AllStats1D()
		features = append(features, sockW, sockMean, sockVar)
		hpRadius, hpMag, hpCov, hpPCC := hpStats[i].Stats2D()
		features = append(features, hpRadius, hpMag, hpCov, hpPCC)
	}

	return features
}

func is1DDecayed(stats []*IncStat, currentTime float64, threshold float64) bool {
	// The slowest decaying statistic is at the end of the slice (lambda = 0.01)
	slowest := stats[len(stats)-1]
	return slowest.DecayedWeight(currentTime) < threshold
}

func isCovDecayed(statsCov []*IncStatCov, currentTime float64, threshold float64) bool {
	slowest := statsCov[len(statsCov)-1]
	return slowest.IsDecayed(currentTime, threshold)
}

// TotalEntries returns the total number of tracked keys across all internal hash tables
func (ns *NetStat) TotalEntries() int {
	return len(ns.HT_MAC_IP) + len(ns.HT_SrcIP) + len(ns.HT_Jitter) +
		len(ns.HT_SrcSock) + len(ns.HT_HH) + len(ns.HT_HpHp)
}

// Cleanup evicts inactive entries whose exponential weights have decayed below threshold.
// Returns the number of evicted entries.
func (ns *NetStat) Cleanup(currentTime float64, threshold float64) int {
	if threshold <= 0 {
		threshold = 0.001
	}
	evicted := 0

	for k, stats := range ns.HT_MAC_IP {
		if is1DDecayed(stats, currentTime, threshold) {
			delete(ns.HT_MAC_IP, k)
			evicted++
		}
	}

	for k, stats := range ns.HT_SrcIP {
		if is1DDecayed(stats, currentTime, threshold) {
			delete(ns.HT_SrcIP, k)
			evicted++
		}
	}

	for k, stats := range ns.HT_Jitter {
		if is1DDecayed(stats, currentTime, threshold) {
			delete(ns.HT_Jitter, k)
			delete(ns.LastTime, k)
			evicted++
		}
	}

	for k, stats := range ns.HT_SrcSock {
		if is1DDecayed(stats, currentTime, threshold) {
			delete(ns.HT_SrcSock, k)
			evicted++
		}
	}

	for k, statsCov := range ns.HT_HH {
		if isCovDecayed(statsCov, currentTime, threshold) {
			delete(ns.HT_HH, k)
			evicted++
		}
	}

	for k, statsCov := range ns.HT_HpHp {
		if isCovDecayed(statsCov, currentTime, threshold) {
			delete(ns.HT_HpHp, k)
			evicted++
		}
	}

	return evicted
}
