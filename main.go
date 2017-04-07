package main

import (
    "fmt"
    "github.com/nikofil/gopacketcache/lib"
)

func main() {
    packetChannel, err := gopacketcache.OpenOffline("http.cap")
    if err == nil {
        for packet := range packetChannel {
            fmt.Println("packet", packet)
        }
    }
}
