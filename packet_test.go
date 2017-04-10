package gopacketcache

import (
    "testing"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

func getOnePacket(t *testing.T) *Packet {
    packetChannel, err := OpenOffline("examples/http.cap")
    if err != nil {
        t.Errorf("Got error in OpenOffline: %s", err)
    }
    packet := <- packetChannel
    return packet
}

func getEmptyPacket() *Packet {
    emptyPacket := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet,
        gopacket.Default)
    return &Packet{emptyPacket}
}

func TestOpenOffline(t *testing.T) {
    packetNum := 0
    packetChannel, err := OpenOffline("examples/http.cap")
    for range packetChannel {
        packetNum++
    }
    if err != nil {
        t.Errorf("Got error in OpenOffline: %s", err)
    }
    if packetNum != 43 {
        t.Errorf("Wrong packet count from pcap dump: %d", packetNum)
    }
}

func TestOpenOfflineError(t *testing.T) {
    _, err := OpenOffline("doesnotexist.cap")
    if err == nil {
        t.Error("Did not get error for missing file")
    }
}

func TestPacketPorts(t *testing.T) {
    packet := getOnePacket(t)
    src, dst, err := packet.GetPorts()
    if err != nil {
        t.Errorf("Error retrieving ports: %s", err)
    }
    if src != 3372 || dst != 80 {
        t.Errorf("Wrong ports: %d -> %d, expected 3372 -> 80", src, dst)
    }
}

func TestPacketMissingPorts(t *testing.T) {
    packet := getEmptyPacket()
    _, _, err := packet.GetPorts()
    if err == nil {
        t.Error("Packet missing transport layer did not throw error")
    }
    if err.Error() != (PortError{}).Error() {
        t.Error("Wrong error message received")
    }
}

func TestPacketIPv4Addrs(t *testing.T) {
    packet := getOnePacket(t)
    src, dst, err := packet.GetIPv4Addrs()
    if err != nil {
        t.Errorf("Error retrieving IPs: %s", err)
    }
    if src != "145.254.160.237" || dst != "65.208.228.223" {
        t.Errorf("Wrong IPs: %s -> %s, expected 145.254.160.237 -> " +
            "65.208.228.223", src, dst)
    }
}

func TestPacketMissingIPv4(t *testing.T) {
    packet := getEmptyPacket()
    _, _, err := packet.GetIPv4Addrs()
    if err == nil {
        t.Error("Packet missing IPv4 layer did not throw error")
    }
    if err.Error() != (IPv4Error{}).Error() {
        t.Error("Wrong error message received")
    }
}

func TestPacketTCPTuple(t *testing.T) {
    packet := getOnePacket(t)
    tuple, err := packet.GetTCPTuple()
    if err != nil {
        t.Errorf("Error retrieving tuple: %s", err)
    }
    srcPort, dstPort, _ := packet.GetPorts()
    srcIP, dstIP, _ := packet.GetIPv4Addrs()
    if srcPort != tuple.fromPort || dstPort != tuple.toPort ||
       srcIP != tuple.fromIPv4 || dstIP != tuple.toIPv4 {
        t.Error("Mismatching tuple info")
    }
}

func TestPacketTCPTupleError(t *testing.T) {
    packet := getEmptyPacket()
    _, err := packet.GetTCPTuple()
    if err == nil {
        t.Error("Empty packet did not throw error")
    }
}
