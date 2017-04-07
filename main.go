package main

import (
    "fmt"
    "github.com/nikofil/gopacketcache/lib"
)

func main() {
    packetChannel, err := gopacketcache.OpenOffline("http.cap")
    if err == nil {
        i := 1
        for packet := range packetChannel {
            fmt.Printf("Packet %d: ", i)
            srcPort, errSrc := packet.SrcPort()
            dstPort, errDst := packet.DstPort()
            if errSrc == nil && errDst == nil {
                fmt.Printf("Port %d -> %d\n", srcPort, dstPort)
            } else {
                fmt.Println(err)
            }
            i++
        }
    }
}
