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

// The PortError type represents an error while retrieving the ports
// of a packet.
type PortError struct{}

func (PortError) Error() string {
    return "This packet does not have a TCP layer."
}

// SrcPort returns the source port of a packet, or an error if the packet
// does not have a TCP layer.
func (packet *Packet) SrcPort() (Port, error) {
    if layer := (*packet.packet).Layer(layers.LayerTypeTCP);
                layer != nil {
        return Port(layer.(*layers.TCP).SrcPort), nil
    }
    return 0, PortError{}
}

// DstPort returns the destination port of a packet, or an error if the packet
// does not have a TCP layer.
func (packet *Packet) DstPort() (Port, error) {
    if layer := (*packet.packet).Layer(layers.LayerTypeTCP);
        layer != nil {
        return Port(layer.(*layers.TCP).DstPort), nil
    }
    return 0, PortError{}
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
