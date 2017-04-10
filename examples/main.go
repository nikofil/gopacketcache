package main

import (
    "fmt"
    "flag"
    "time"
    "os"
    "os/signal"
    "github.com/nikofil/gopacketcache"
    "github.com/google/gopacket/pcap"
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
    var (
        packetChannel <-chan *gopacketcache.Packet
        err error
    )

    iface := flag.String("interface", "", "Interface to listen to for packets")
    filename := flag.String("filename", "http.cap", "File to read packets from")
    cacheMinutes := flag.Int("cache-mins", 5, "Number of minutes to cache packets")

    flag.Parse()

    signalChannel := make(chan os.Signal, 1)
    signal.Notify(signalChannel, os.Interrupt)
    intSignal := false

    packetCache := gopacketcache.NewPacketCache(*cacheMinutes)
    if *iface == "" {
        packetChannel, err = gopacketcache.OpenOffline(*filename, packetCache)
    }  else {
        packetChannel, err = gopacketcache.OpenLive(*iface, 1024, false, time.Duration(-1),
                                                    packetCache, pcap.OpenLive)
    }
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
            select {
            case <-signalChannel:
                fmt.Println("Received interrupt signal")
                intSignal = true
            default:
            }
            if intSignal {
                break
            }
            i++
        }
        fmt.Println()
        fmt.Println("Number of cached packets:", len(packetCache.GetCachedStats()))
        fmt.Println("Source ports count:\n", srcMap)
        fmt.Println("Destination ports count:\n", dstMap)
    } else {
        fmt.Println("Error:", err)
    }
}
