package gopacketcache

import (
	"testing"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

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
    packetChannel, err := OpenOffline("examples/http.cap")
    if err != nil {
        t.Errorf("Got error in OpenOffline: %s", err)
    }
    packet := <- packetChannel
    if src, err := packet.SrcPort(); src != 80 || err != nil {
        t.Errorf("Wrong source port: %d, Error: %s", src, err)
    }
    if dst, err := packet.DstPort(); dst != 3372 || err != nil {
        t.Errorf("Wrong destination port: %d, Error: %s", dst, err)
    }
}

func TestPacketMissingPorts(t *testing.T) {
    packetData := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet,
                                     gopacket.Default)
    packet := Packet{&packetData}
    _, srcErr := packet.SrcPort()
    _, dstErr := packet.DstPort()
    if srcErr == nil || dstErr == nil {
        t.Error("Packet missing transport layer did not throw error")
    }
    if srcErr.Error() != dstErr.Error() {
        t.Error("Inconsistent errors by missing src and dst ports")
    }
}
