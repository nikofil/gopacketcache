package main

import (
    "fmt"
    "github.com/nikofil/gopacketcache"
)

type PortCounts map[gopacketcache.Port]uint

func (portCounts PortCounts) String() string {
    s := ""
    for port, count := range portCounts {
        s += fmt.Sprintf("\tPort %d: %d times\n", port, count)
    }
    return s
}

func main() {
    packetChannel, err := gopacketcache.OpenOffline("http.cap")
    if err == nil {
        i := 1
        srcMap := make(PortCounts)
        dstMap := make(PortCounts)
        for packet := range packetChannel {
            fmt.Printf("Packet %d: ", i)
            srcPort, errSrc := packet.SrcPort()
            dstPort, errDst := packet.DstPort()
            if errSrc == nil && errDst == nil {
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
