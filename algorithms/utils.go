package algorithms

import "sync"

// paddedMutex is a mutex with padding to avoid false sharing.
// sync.Mutex is 8 bytes on 64-bit systems.
// We pad to 64 bytes (cache line size).
type paddedMutex struct {
	sync.Mutex
	_ [56]byte
}
