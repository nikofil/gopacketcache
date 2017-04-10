package gopacketcache

import (
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

// The Packet type wraps gopacket.Packet and provides methods for getting
// the source and destination port of the contained packet.
type Packet struct {
    packet *gopacket.Packet
}

// The Port type represents a port number.
type Port uint16

// The IPv4Addr type represents an IPv4 address.
type IPv4Addr string

// The PortError type represents an error while retrieving the ports
// of a packet.
type PortError struct{}

func (PortError) Error() string {
    return "This packet does not have a TCP layer."
}

// The IPv4Error type represents an error while retrieving the IPv4 addresses
// of a packet.
type IPv4Error struct{}

func (IPv4Error) Error() string {
    return "This packet does not have an IPv4 layer."
}

// GetPorts returns the source and destination ports of a packet, or an error
// if the packet does not have a TCP layer.
func (packet *Packet) GetPorts() (Port, Port, error) {
    if layer := (*packet.packet).Layer(layers.LayerTypeTCP); layer != nil {
        srcPort := Port(layer.(*layers.TCP).SrcPort)
        dstPort := Port(layer.(*layers.TCP).DstPort)
        return srcPort, dstPort, nil
    }
    return 0, 0, PortError{}
}

// GetIPv4Addrs returns the source and destination IPv4 addresses of a packet,
// or an error if the packet does not have a IP layer.
func (packet *Packet) GetIPv4Addrs() (IPv4Addr, IPv4Addr, error) {
    if layer := (*packet.packet).Layer(layers.LayerTypeIPv4); layer != nil {
        ipv4From := IPv4Addr(layer.(*layers.IPv4).SrcIP.String())
        ipv4To := IPv4Addr(layer.(*layers.IPv4).DstIP.String())
        return ipv4From, ipv4To, nil
    }
    return "", "", IPv4Error{}
}

// The TCPTuple type contains all the information that identifies a TCP
// connection, meaning the source and destination IPs and ports.
type TCPTuple struct {
    fromPort Port
    toPort Port
    fromIPv4 IPv4Addr
    toIPv4 IPv4Addr
}

// GetTCPTuple returns a tuple containing the source and destination IPv4
// addresses and ports. If the packet does not have a TCP or IPv4 layer,
// it returns an error instead.
func (packet *Packet) GetTCPTuple() (*TCPTuple, error) {
    var err error
    tuple := TCPTuple{}
    tuple.fromIPv4, tuple.toIPv4, err = packet.GetIPv4Addrs()
    if err != nil {
        return &TCPTuple{}, err
    }
    tuple.fromPort, tuple.toPort, err = packet.GetPorts()
    if err != nil {
        return &TCPTuple{}, err
    }
    return &tuple, nil
}

func cachePackets(handle *pcap.Handle) chan *Packet {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).
        Packets()
    var cachedPackets chan *Packet

    cachedPackets = make(chan *Packet)

    go func() {
        defer close(cachedPackets)
        defer handle.Close()

        for packet := range packetSource {
            cachedPackets <- &Packet{&packet}
        }
    }()

    return cachedPackets
}

// OpenLive opens a device for reading its packets.
// It takes as parameters the maximum length of the packet to read, whether
// to set the interface into promiscuous mode and the timeout to buffer
// for packets.
// It returns a channel for the client to read the packets from.
func OpenLive(device string, snaplen int32, promisc bool,
              timeout time.Duration) (chan *Packet, error) {
    // TODO add tests
    var (
        handle *pcap.Handle
        err error
    )

    handle, err = pcap.OpenLive(device, snaplen, promisc, timeout)
    if err != nil {
        return nil, err
    }

    cachedPackets := cachePackets(handle)

    return cachedPackets, nil
}


// OpenOffline opens a pcap file for reading the packets it contains.
// It takes as the parameter the name of the file.
// It returns a channel for the client to read the packets from.
func OpenOffline(pcapFile string) (chan *Packet, error) {
    var (
        handle *pcap.Handle
        err error
    )

    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil {
        return nil, err
    }

    cachedPackets := cachePackets(handle)

    return cachedPackets, nil
}
