package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketMetaData struct {
	Timestamp time.Time
	Length    int
	SrcMac    string
	DstMac    string
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
}

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
		handle, err = pcap.OpenLive(*interfaceName, 1600, true, pcap.BlockForever)
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

func parsePacket(packet gopacket.Packet) *PacketMetaData {
	meta := &PacketMetaData{}

	meta.Timestamp = packet.Metadata().Timestamp
	meta.Length = packet.Metadata().Length

	if meta.Timestamp.IsZero() {
		meta.Timestamp = time.Now()
	}

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		meta.SrcMac = eth.SrcMAC.String()
		meta.DstMac = eth.DstMAC.String()
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)
	meta.SrcIP = ip.SrcIP.String()
	meta.DstIP = ip.DstIP.String()

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
	} else {
		meta.Protocol = "Other"
	}

	return meta
}

func processExtractedPacket(meta *PacketMetaData) {
	fmt.Printf("[%s] [%s] %s:%s -> %s:%s | %d bytes\n",
		meta.Timestamp.Format("15:04:05.000000"),
		meta.Protocol,
		meta.SrcIP, meta.SrcPort,
		meta.DstIP, meta.DstPort,
		meta.Length,
	)
}
