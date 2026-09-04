package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketMetaData holds parsed fields from a single packet
type PacketMetaData struct {
	Timestamp float64
	Length    int
	SrcMac    string
	DstMac    string
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
}

// parses packet data into PacketMetaData struct
func parsePacket(packet gopacket.Packet) *PacketMetaData {
	meta := &PacketMetaData{}

	md := packet.Metadata()
	if md != nil {
		meta.Length = md.Length
		meta.Timestamp = float64(md.Timestamp.UnixNano()) / 1e9 // one billion
	}

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		meta.SrcMac = eth.SrcMAC.String()
		meta.DstMac = eth.DstMAC.String()
	}

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		meta.Protocol = "ARP"
		meta.SrcIP = net.IP(arp.SourceProtAddress).String()
		meta.DstIP = net.IP(arp.DstProtAddress).String()
		meta.SrcPort = "0"
		meta.DstPort = "0"
		return meta
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		meta.SrcIP = ip.SrcIP.String()
		meta.DstIP = ip.DstIP.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		meta.SrcIP = ip6.SrcIP.String()
		meta.DstIP = ip6.DstIP.String()
	} else {
		// Non-IP
		return nil
	}

	// Transport Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		meta.SrcPort = tcp.SrcPort.String()
		meta.DstPort = tcp.DstPort.String()
		meta.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		meta.SrcPort = udp.SrcPort.String()
		meta.DstPort = udp.DstPort.String()
		meta.Protocol = "UDP"
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		meta.Protocol = "ICMP"
		meta.SrcPort = "0"
		meta.DstPort = "0"
	} else {
		meta.Protocol = "Other"
		meta.SrcPort = "0"
		meta.DstPort = "0"
	}

	return meta
}
