package ztrouter

import (
	"context"
	"sync"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

// defaultMaxStreamBuffer bounds how many response-body bytes may sit queued
// between the agent mTLS read loop and a slow client writer before the
// stream is aborted. Streaming responses have no flow control on the agent
// leg — the agent sends chunks as fast as it reads them from the upstream —
// so the router must buffer the burst. 32 MiB absorbs any realistic burst
// while still bounding per-request memory.
const defaultMaxStreamBuffer = 32 << 20

// msgOverheadBytes is charged against the byte cap per queued message in
// addition to its body length. Without it, a flood of tiny chunks (say,
// 1-byte bodies) would pass the cap while accumulating millions of Message
// structs — far more real memory than the cap suggests.
const msgOverheadBytes = 256

// msgQueue is an unbounded-order, byte-capped FIFO between the agent
// dispatch callback (producer, runs on the agent connection's read loop and
// must never block) and the per-request pump goroutine (consumer).
//
// It replaces the previous buffered-channel-with-default-drop pattern, which
// silently discarded streaming chunks whenever more than the channel
// capacity were in flight — truncating download bodies mid-stream and, when
// the IsLastChunk message was dropped, hanging the response until timeout.
// Chunks are never dropped: if the byte cap is exceeded the queue flips to
// overflow and the stream is aborted loudly instead.
type msgQueue struct {
	mu       sync.Mutex
	items    []*common.Message
	head     int // index of the next item to pop; see pop() for compaction
	bytes    int64
	maxBytes int64
	overflow bool
	signal   chan struct{} // capacity 1; coalesced wake-up for the consumer
}

func newMsgQueue(maxBytes int64) *msgQueue {
	if maxBytes <= 0 {
		maxBytes = defaultMaxStreamBuffer
	}
	return &msgQueue{maxBytes: maxBytes, signal: make(chan struct{}, 1)}
}

// push appends m. It never blocks: this is called from the agent read loop,
// and blocking there would stall every multiplexed request on the agent
// connection. Once the byte cap is exceeded the queue is marked overflowed
// and all subsequent messages are discarded — the consumer aborts the stream,
// so continuity is already lost.
func (q *msgQueue) push(m *common.Message) {
	size := int64(msgOverheadBytes)
	if m != nil && m.HTTP != nil {
		size += int64(len(m.HTTP.Body))
	}

	q.mu.Lock()
	if q.overflow {
		q.mu.Unlock()
		return
	}
	if q.bytes+size > q.maxBytes {
		q.overflow = true
		q.mu.Unlock()
		q.wake()
		return
	}
	q.items = append(q.items, m)
	q.bytes += size
	q.mu.Unlock()
	q.wake()
}

// pop removes and returns the head of the queue. ok is false when empty.
//
// A head index is used instead of re-slicing (items = items[1:]) so the
// backing array can be compacted: re-slicing permanently retains every
// pointer slot ever pushed, growing memory with total throughput rather
// than queue depth.
func (q *msgQueue) pop() (m *common.Message, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head == len(q.items) {
		return nil, false
	}
	m = q.items[q.head]
	q.items[q.head] = nil // let the chunk body be collected promptly
	q.head++
	if m != nil && m.HTTP != nil {
		q.bytes -= int64(len(m.HTTP.Body))
	}
	q.bytes -= msgOverheadBytes

	switch {
	case q.head == len(q.items):
		// Drained — release the backing array entirely.
		q.items = nil
		q.head = 0
	case q.head >= 256 && q.head*2 >= len(q.items):
		// Mostly-consumed — shift the live window to the front so the
		// backing array size tracks queue depth, not total throughput.
		q.items = append(q.items[:0], q.items[q.head:]...)
		q.head = 0
	}
	return m, true
}

func (q *msgQueue) overflowed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.overflow
}

func (q *msgQueue) wake() {
	select {
	case q.signal <- struct{}{}:
	default:
	}
}

// pump forwards queued messages to out in order, blocking on the consumer
// (that's the point: backpressure lands here, in a per-request goroutine,
// not on the shared agent read loop). On overflow it delivers a final
// Error-carrying message so the download loop aborts the response, then
// exits. It returns when ctx is cancelled or stop is closed.
//
// Wake-up correctness: the coalesced capacity-1 signal cannot be "lost".
// push makes the item visible (under q.mu) *before* wake(), and pump
// re-checks the queue via pop() after *every* signal receipt. So whenever
// pump blocks on q.signal, any item pushed after its last pop() has either
// left a token in the channel (wake found it empty → pump unblocks) or
// wake found the channel full — in which case that token is still there
// and unblocks pump anyway; the follow-up pop() then observes the item.
// A drained "stale" token merely causes one extra empty pop(), never a
// missed item. Exercised by TestMsgQueue_PumpStress_NoLostWakeup.
func (q *msgQueue) pump(ctx context.Context, stop <-chan struct{}, out chan<- *common.Message) {
	for {
		if m, ok := q.pop(); ok {
			select {
			case out <- m:
				continue
			case <-ctx.Done():
				return
			case <-stop:
				return
			}
		}
		if q.overflowed() {
			m := &common.Message{Error: "response stream buffer overflow: client reads slower than the agent sends and the buffer cap was reached"}
			select {
			case out <- m:
			case <-ctx.Done():
			case <-stop:
			}
			return
		}
		select {
		case <-q.signal:
		case <-ctx.Done():
			return
		case <-stop:
			return
		}
	}
}
