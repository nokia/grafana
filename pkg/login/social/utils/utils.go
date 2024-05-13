package utils

import (
	"sync/atomic"
	"time"
)

// InitTimeTicker starts a go routine which updates currentTimestamp every second
func InitTimeTicker() {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for tm := range ticker.C {
			t := uint64(tm.Unix())
			currentTimestamp.Store(t)
		}
	}()
}

var currentTimestamp = func() *atomic.Uint64 {
	var x atomic.Uint64
	x.Store(uint64(time.Now().Unix()))
	return &x
}()

// UnixTimestamp returns the current unix timestamp.
func UnixTimestamp() uint64 {
	return currentTimestamp.Load()
}

func GetCertRefreshInterval(dur time.Duration) uint64 {
	currTime := time.Now()
	tmWithRefreshInterval := currTime.Add(dur)
	diff := currTime.Unix() - tmWithRefreshInterval.Unix()
	return uint64(diff)
}
