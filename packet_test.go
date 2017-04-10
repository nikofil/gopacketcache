package gopacketcache

import (
    "testing"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "time"
    "github.com/google/gopacket/pcap"
)

func getOnePacket(t *testing.T) (*Packet, error) {
    packetChannel, err := OpenOffline("examples/http.cap", nil)
    if err != nil {
        t.Errorf("Got error getting single packet: %s", err)
        return nil, err
    }
    packet := <-packetChannel
    return packet, nil
}

func getOneUDPPacket(t *testing.T) (*Packet, error) {
    packetChannel, err := OpenOffline("examples/http.cap", nil)
    if err != nil {
        t.Errorf("Got error getting single packet: %s", err)
        return nil, err
    }
    for packet := range(packetChannel) {
        if packet.Packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
            return packet, nil
        }
    }
    return nil, nil
}

func getEmptyPacket() *Packet {
    emptyPacket := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet,
        gopacket.Default)
    return &Packet{emptyPacket}
}

func TestOpenOffline(t *testing.T) {
    packetNum := 0
    packetChannel, err := OpenOffline("examples/http.cap", nil)
    if err != nil {
        t.Errorf("Got error in OpenOffline: %s", err)
    } else {
        for range packetChannel {
            packetNum++
        }
        if packetNum != 43 {
            t.Errorf("Wrong packet count from pcap dump: %d", packetNum)
        }
    }
}

func TestOpenOfflineError(t *testing.T) {
    _, err := OpenOffline("doesnotexist.cap", nil)
    if err == nil {
        t.Error("Did not get error for missing file")
    }
}

type TestPcapImpl struct{
    pcapFile string
}

// OpenLive overrides the real OpenLive implementation for testing.
func (testPcap *TestPcapImpl) openLive(device string, snaplen int32, promisc bool,
              timeout time.Duration) (*pcap.Handle, error) {
    return pcap.OpenOffline(testPcap.pcapFile)
}

func TestOpenLive(t *testing.T) {
    packetNum := 0
    testPcapImpl := TestPcapImpl{"examples/http.cap"}
    packetChannel, err := OpenLive("eth0", 100, false, time.Minute, nil, testPcapImpl.openLive)
    if err != nil {
        t.Errorf("Got error in OpenLive: %s", err)
    } else {
        for range packetChannel {
            packetNum++
        }
        if packetNum != 43 {
            t.Errorf("Wrong packet count in live capturing: %d", packetNum)
        }
    }
}

func TestOpenLiveError(t *testing.T) {
    testPcapImpl := TestPcapImpl{"doesnotexist.cap"}
    _, err := OpenLive("dev", 100, false, time.Minute, nil, testPcapImpl.openLive)
    if err == nil {
        t.Error("Did not get error for missing file")
    }
}

func TestPacketPorts(t *testing.T) {
    packet, _ := getOnePacket(t)
    src, dst, err := packet.GetPorts()
    if err != nil {
        t.Errorf("Error retrieving ports: %s", err)
    } else if src != 3372 || dst != 80 {
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
    packet, _ := getOnePacket(t)
    src, dst, err := packet.GetIPv4Addrs()
    if err != nil {
        t.Errorf("Error retrieving IPs: %s", err)
    } else if src != "145.254.160.237" || dst != "65.208.228.223" {
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
    packet, _ := getOnePacket(t)
    tuple, err := packet.GetTCPTuple()
    if err != nil {
        t.Errorf("Error retrieving tuple: %s", err)
    } else {
        srcPort, dstPort, _ := packet.GetPorts()
        srcIP, dstIP, _ := packet.GetIPv4Addrs()
        if srcPort != tuple.FromPort || dstPort != tuple.ToPort ||
            srcIP != tuple.FromIPv4 || dstIP != tuple.ToIPv4 {
            t.Error("Mismatching tuple info")
        }
    }
}

func TestPacketTCPTupleError(t *testing.T) {
    packet := getEmptyPacket()
    _, err := packet.GetTCPTuple()
    if err == nil {
        t.Error("Empty packet did not throw error")
    }
    udpPacket, _ := getOneUDPPacket(t)
    _, err = udpPacket.GetTCPTuple()
    if err == nil {
        t.Error("UDP packet did not throw error")
    }
}
