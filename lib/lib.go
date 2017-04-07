package gopacketcache

import (
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)


func cachePackets(handle *pcap.Handle) chan *gopacket.Packet {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).
        Packets()
    var cachedPackets chan *gopacket.Packet

    cachedPackets = make(chan *gopacket.Packet)

    go func() {
        defer close(cachedPackets)
        defer handle.Close()

        for packet := range packetSource {
            cachedPackets <- &packet
        }
    }()

    return cachedPackets
}

// OpenLive opens a device for reading its packets.
// It takes as parameters the maximum length of the packet 
func OpenLive(device string, snaplen int32, promisc bool,
              timeout time.Duration) (chan *gopacket.Packet, error) {
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


func OpenOffline(pcapFile string) (chan *gopacket.Packet, error) {
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
