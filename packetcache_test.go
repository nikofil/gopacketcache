package gopacketcache

import (
    "testing"
    "time"
)

type TestTimeImpl struct {
    curTime time.Time
}

func (timeImpl *TestTimeImpl) Now() time.Time {
    return timeImpl.curTime
}

func TestNewPacketCache(t *testing.T) {
    if cache := NewPacketCache(10); cache.minutesCached != 10 {
        t.Error("Wrong number of minutes")
    }
}

func TestPacketCache_InsertError(t *testing.T) {
    cache := NewPacketCache(0)
    packet, _ := getOneUDPPacket(t)
    if err := cache.Insert(packet); err == nil {
        t.Error("Did not get error on UDP packet caching")
    }
}

func TestPacketCache_GetCachedStats(t *testing.T) {
    cache := NewPacketCache(10)
    mockTime := TestTimeImpl{time.Now()}
    cache.timeNow = mockTime.Now
    packet, _ := getOnePacket(t)
    for i := 0; i < 9; i ++ {
        cache.Insert(packet)
        mockTime.curTime = mockTime.curTime.Add(time.Minute)
        if len(cache.GetCachedStats()) != i + 1 {
            t.Error("Wrong number of cached packets")
        }
    }
    mockTime.curTime = mockTime.curTime.Add(time.Second)
    for i := 0; i < 9; i ++ {
        mockTime.curTime = mockTime.curTime.Add(time.Minute)
        if len(cache.GetCachedStats()) != 8 - i {
            t.Error("Wrong number of cached packets after cache invalidation")
        }
    }
    for i := 0; i < 9; i ++ {
        mockTime.curTime = mockTime.curTime.Add(time.Minute)
        if len(cache.GetCachedStats()) != 0 {
            t.Error("Found packets in empty cache")
        }
    }
}

func TestPacketCache_OpenOffline(t *testing.T) {
    cache := NewPacketCache(10)
    mockTime := TestTimeImpl{time.Now()}
    cache.timeNow = mockTime.Now
    if packetChannel, err := OpenOffline("examples/http.cap", cache); err != nil {
        t.Error(err)
    } else {
        i := 0
        for packet := range packetChannel {
            if _, err := packet.GetTCPTuple(); err == nil {
                i++
            }
        }
        if i != len(cache.GetCachedStats()) {
            t.Error("Wrong number of cached packets")
        }
    }
}
