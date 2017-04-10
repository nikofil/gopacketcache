// Package gopacketcache provides the Packet wrapper and the cache that
// can be used for caching incoming packets' information.
package gopacketcache

import (
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "fmt"
)

// Packet wraps gopacket.Packet and provides methods for getting
// the source and destination port of the contained packet.
type Packet struct {
    // Packet is the wrapped packet.
    Packet gopacket.Packet
}

// Port represents a port number.
type Port uint16

// IPv4Addr represents an IPv4 address.
type IPv4Addr string

// PortError represents an error while retrieving the ports of a packet.
type PortError struct{}

func (PortError) Error() string {
    return "This packet does not have a TCP layer."
}

// IPv4Error type represents an error while retrieving the IPv4 addresses
// of a packet.
type IPv4Error struct{}

func (IPv4Error) Error() string {
    return "This packet does not have an IPv4 layer."
}

// GetPorts returns the source and destination ports of a packet, or an error
// if the packet does not have a TCP layer.
func (packet *Packet) GetPorts() (Port, Port, error) {
    if layer := packet.Packet.Layer(layers.LayerTypeTCP); layer != nil {
        srcPort := Port(layer.(*layers.TCP).SrcPort)
        dstPort := Port(layer.(*layers.TCP).DstPort)
        return srcPort, dstPort, nil
    }
    return 0, 0, PortError{}
}

// GetIPv4Addrs returns the source and destination IPv4 addresses of a packet,
// or an error if the packet does not have a IP layer.
func (packet *Packet) GetIPv4Addrs() (IPv4Addr, IPv4Addr, error) {
    if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
        ipv4From := IPv4Addr(layer.(*layers.IPv4).SrcIP.String())
        ipv4To := IPv4Addr(layer.(*layers.IPv4).DstIP.String())
        return ipv4From, ipv4To, nil
    }
    return "", "", IPv4Error{}
}

// TCPTuple contains all the information that identifies a TCP
// connection, meaning the source and destination IPs and ports.
type TCPTuple struct {
    // FromPort is the source port.
    FromPort Port
    // ToPort is the destination port.
    ToPort Port
    // FromIPv4 is the source IPv4 address.
    FromIPv4 IPv4Addr
    // ToIPv4 is the destination IPv4 address.
    ToIPv4 IPv4Addr
}

// GetTCPTuple returns a tuple containing the source and destination IPv4
// addresses and ports. If the packet does not have a TCP or IPv4 layer,
// it returns an error instead.
func (packet *Packet) GetTCPTuple() (*TCPTuple, error) {
    var err error
    tuple := TCPTuple{}
    tuple.FromIPv4, tuple.ToIPv4, err = packet.GetIPv4Addrs()
    if err != nil {
        return &TCPTuple{}, err
    }
    tuple.FromPort, tuple.ToPort, err = packet.GetPorts()
    if err != nil {
        return &TCPTuple{}, err
    }
    return &tuple, nil
}

// cachePackets takes a pcap handle and a packet cache. It caches the incoming
// packets and returns a channel that also contains these packets, wrapped with
// the library's Packet type, for further processing.
// If nil is passed as the cache, the packets are not cached.
func cachePackets(handle *pcap.Handle, pcache *PacketCache) chan *Packet {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).
        Packets()
    var cachedPackets chan *Packet

    cachedPackets = make(chan *Packet)

    go func() {
        defer close(cachedPackets)
        defer handle.Close()

        for packet := range packetSource {
            wrappedPacket := &Packet{packet}
            if pcache != nil {
                err := pcache.Insert(wrappedPacket)
                if err != nil {
                    fmt.Println("Could not cache packet:", err)
                }
            }
            cachedPackets <- wrappedPacket
        }
    }()

    return cachedPackets
}

// pcapImpl is used for overriding pcap.OpenLive for testing.
type pcapImpl func(string, int32, bool, time.Duration) (*pcap.Handle, error)

// OpenLive opens a device for reading its packets.
// It takes as parameters the maximum length of the packet to read, whether
// to set the interface into promiscuous mode, the timeout to buffer
// for packets, optionally a packet cache for caching the packets in and an
// implementation for the OpenLive used internally.
// Nil can be used for a packet cache in order not to cache the packets.
// It returns a channel for the client to read the packets from.
func OpenLive(device string, snaplen int32, promisc bool,
              timeout time.Duration, pcache *PacketCache,
              pcapimpl pcapImpl) (chan *Packet, error) {
    var (
        handle *pcap.Handle
        err error
    )

    handle, err = pcapimpl(device, snaplen, promisc, timeout)
    if err != nil {
        return nil, err
    }

    cachedPackets := cachePackets(handle, pcache)

    return cachedPackets, nil
}


// OpenOffline opens a pcap file path for reading the packets it contains and
// optionally a packet cache for caching the packets retrieved.
// Nil can be used for a packet cache in order not to cache the packets.
// It takes as the parameter the name of the file.
// It returns a channel for the client to read the packets from.
func OpenOffline(pcapFile string, pcache *PacketCache) (<-chan *Packet, error) {
    var (
        handle *pcap.Handle
        err error
    )

    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil {
        return nil, err
    }

    cachedPackets := cachePackets(handle, pcache)

    return cachedPackets, nil
}
