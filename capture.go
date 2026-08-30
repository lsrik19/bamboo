package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

// manages interfacing 
func main() {
	pcapPath := flag.String("f", "", "PCAP file path")
	interfaceName := flag.String("i", "", "Live interface name")
	flag.Parse()

	if (*pcapPath == "" && *interfaceName == "") || (*pcapPath != "" && *interfaceName != "") {
		fmt.Println("can't pass both PCAP and Live traffic")
		flag.Usage()
		os.Exit(1)
	}

	var handle *pcap.Handle
	var err error

	if *pcapPath != "" {
		fmt.Printf("Traffic from PCAP file: %s\n", *pcapPath)
		handle, err = pcap.OpenOffline(*pcapPath)

		if err != nil {
			log.Fatalf("ERROR: could not open PCAP file: %v", err)
		}
	} else {
		fmt.Printf("Traffic from interface: %s\n", *interfaceName)
		handle, err = pcap.OpenLive(*interfaceName, 256, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("ERROR: could not open Interface: %v", err)
		}
	}

	defer handle.Close()

	stopchan := make(chan os.Signal, 1)
	signal.Notify(stopchan, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	fmt.Printf("Processing Stream.....")

	for {
		select {
		case <-stopchan:
			fmt.Printf("Keyboard interrupt received, stopping now.\n")
			return

		case packet, ok := <-packets:
			if !ok {
				fmt.Printf("Reached the end of stream.\n")
				return
			}
			
			meta := parsePacket(packet)
			if meta == nil {
				continue // non IP traffic
			}
			processExtractedPacket(meta)
		}

	}

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

	// IPv4 Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		meta.SrcIP = ip.SrcIP.String()
		meta.DstIP = ip.DstIP.String()
		// ignoring IPv6 for now
		// } else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		// 	ip6, _ := ip6Layer.(*layers.IPv6)
		// 	meta.SrcIP = ip6.SrcIP.String()
		// 	meta.DstIP = ip6.DstIP.String()
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
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
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

// temporary logging function for testing
func processExtractedPacket(meta *PacketMetaData) {
	fmt.Printf("[%s] %s:%s -> %s:%s | %d bytes\n",
		meta.Protocol,
		meta.SrcIP, meta.SrcPort,
		meta.DstIP, meta.DstPort,
		meta.Length,
	)
}
