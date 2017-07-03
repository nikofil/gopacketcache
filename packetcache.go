package gopacketcache

import (
    "time"
    "sync"
    "github.com/google/gopacket"
)

// CachedInfo holds the cached information of one packet.
type CachedInfo struct {
    // SrcIP is the source IPv4 IP address of the packet.
    SrcIP IPv4Addr
    // DstPort is the destination port of the packet.
    DstPort Port
    // Date is the timestamp of the packet.
    Date time.Time
}

// PacketCache is the structure that contains all the cached data of the
// associated captures, holding the information for some minutes. The number
// of minutes is provided when creating the cache, using NewPacketCache.
type PacketCache struct {
    // cache holds an array of all cached information per minute. Each subarray
    // is the list of information for that minute. If no packets were cached in
    // a minute, an entry won't be used for that minute.
    cache [][]*CachedInfo
    // mtx is the mutex used for thread safety.
    mtx *sync.Mutex
    // minutesCached is the number of minutes that the cache will keep information for.
    minutesCached int
    // curIndex is the index of the current cache array used.
    curIndex int
    // lastInsert holds the last insertion time for each cache array.
    lastInsert  []time.Time
    // timeNow contains the implementation of time.Now used in the caching mechanism.
    timeNow func() time.Time
}

// NewPacketCache creates a new PacketCache. It takes as a parameter the
// number of minutes for which to hold cached information.
// It returns a pointer to the new PacketCache.
func NewPacketCache(expiryMinutes int) *PacketCache {
    pcache := new(PacketCache)
    pcache.mtx = new(sync.Mutex)
    pcache.minutesCached = expiryMinutes
    // Keep expiryMinutes+1 arrays in order not to overwrite any cached infos before their time
    pcache.lastInsert = make([]time.Time, expiryMinutes + 1)
    pcache.cache = make([][]*CachedInfo, expiryMinutes + 1)
    pcache.timeNow = time.Now
    return pcache
}

// Insert adds a new packet to the cache, with the current time as the timestamp.
// It takes a pointer to a packet.
func (pcache *PacketCache) Insert(packet *Packet) error {
    pTuple, err := packet.GetTCPTuple()
    if err == nil {
        pcache.mtx.Lock()
        curTime := pcache.timeNow()
        cacheInfo := CachedInfo{SrcIP: pTuple.FromIPv4, DstPort: pTuple.ToPort, Date: curTime}
        lastInsert := pcache.lastInsert[pcache.curIndex]
        if lastInsert.IsZero() || lastInsert.Truncate(time.Minute).Add(time.Minute).Before(curTime) {
            // First ever insert, or last insert happened in a previous minute so we change index
            pcache.curIndex = (pcache.curIndex + 1) % len(pcache.cache)
            pcache.lastInsert[pcache.curIndex] = curTime
            pcache.cache[pcache.curIndex] = make([]*CachedInfo, 0, 10)
        }
        pcache.cache[pcache.curIndex] = append(pcache.cache[pcache.curIndex], &cacheInfo)
        pcache.mtx.Unlock()
        return nil
    }
    return err
}

// InsertGoPacket inserts an unwrapped GoPacket packet to the cache.
func (pcache *PacketCache) InsertGoPacket(gpacket *gopacket.Packet) error {
    packet := Packet{*gpacket}
    return pcache.Insert(&packet)
}

// GetCachedStats returns the cached information of the last minutes, as
// determined by the parameter provided on the cache creation.
// It returns an array of pointers to the cached information.
func (pcache *PacketCache) GetCachedStats() []*CachedInfo {
    info := make([]*CachedInfo, 0)
    // Whether we have found the first packet to return, after which we return all the rest
    crossedThreshold := false
    pcache.mtx.Lock()
    timeThreshold := pcache.timeNow().Add(time.Duration(-pcache.minutesCached) * time.Minute)
    nextIdx := (pcache.curIndex + 1) % len(pcache.cache)
    for idx, first := nextIdx, true; first || idx != nextIdx; idx = (idx + 1) % len(pcache.cache) {
        if crossedThreshold {
            // Append all of the cached infos if we have crossed the threshold
            info = append(info, pcache.cache[idx]...)
        } else {
            if pcache.lastInsert[idx].After(timeThreshold) {
                i := 0
                // Find the first packet to actually come after the threshold date
                for i = range pcache.cache[idx] {
                    if pcache.cache[idx][i].Date.After(timeThreshold) {
                        crossedThreshold = true
                        break
                    }
                }
                info = append(info, pcache.cache[idx][i:]...)
            }
            // We're past the first loop
            first = false
        }
    }
    pcache.mtx.Unlock()
    return info
}
