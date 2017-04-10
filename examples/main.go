package main

import (
    "fmt"
    "github.com/nikofil/gopacketcache"
)

type portCounts map[gopacketcache.Port]uint

func (counts portCounts) String() string {
    s := ""
    for port, count := range counts {
        s += fmt.Sprintf("\tPort %d: %d times\n", port, count)
    }
    return s
}

func main() {
    packetCache := gopacketcache.NewPacketCache(1)
    packetChannel, err := gopacketcache.OpenOffline("http.cap", packetCache)
    if err == nil {
        i := 1
        srcMap := make(portCounts)
        dstMap := make(portCounts)
        for packet := range packetChannel {
            fmt.Printf("Packet %d: ", i)
            srcPort, dstPort, err := packet.GetPorts()
            if err == nil {
                fmt.Printf("Port %d -> %d\n", srcPort, dstPort)
                srcMap[srcPort]++
                dstMap[dstPort]++
            } else {
                fmt.Println(err)
            }
            i++
        }
        fmt.Println()
        fmt.Println("Source ports count:\n", srcMap)
        fmt.Println("Destination ports count:\n", dstMap)
    }
}
