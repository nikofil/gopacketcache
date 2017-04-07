package gopacketcache

import (
	"testing"
)

func TestOpenOffline(t *testing.T) {
    packetNum := 0
    packetChannel, err := OpenOffline("../http.cap")
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
    _, err := OpenOffline("../doesnotexist.cap")
    if err == nil {
        t.Errorf("Did not get error for missing file")
    }
}
