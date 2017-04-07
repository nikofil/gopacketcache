package gopacketcache

import (
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)


func cachePackets(handle *pcap.Handle, cachedPackets chan *gopacket.Packet) {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
    defer close(cachedPackets)
    defer handle.Close()

    for packet := range packetSource {
        cachedPackets <- &packet
    }
}


func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (chan *gopacket.Packet, error) {
    var (
        handle *pcap.Handle
        cachedPackets chan *gopacket.Packet
        err error
    )

    handle, err = pcap.OpenLive(device, snaplen, promisc, timeout)
    if err != nil {
        return nil, err
    }

    cachedPackets = make(chan *gopacket.Packet)
    go cachePackets(handle, cachedPackets)

    return cachedPackets, nil
}


func OpenOffline(pcapFile string) (chan *gopacket.Packet, error) {
    var (
        handle *pcap.Handle
        cachedPackets chan *gopacket.Packet
        err error
    )

    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil {
        return nil, err
    }

    cachedPackets = make(chan *gopacket.Packet)
    go cachePackets(handle, cachedPackets)

    return cachedPackets, nil
}
