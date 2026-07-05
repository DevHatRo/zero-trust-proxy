package ztrouter

import (
	"context"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

func chunkMsg(body []byte) *common.Message {
	return &common.Message{HTTP: &common.HTTPData{Body: body, IsStream: true}}
}

func TestMsgQueue_FIFOAndByteAccounting(t *testing.T) {
	q := newMsgQueue(1 << 20)

	for i := 0; i < 50; i++ {
		q.push(chunkMsg([]byte{byte(i)}))
	}
	for i := 0; i < 50; i++ {
		m, ok := q.pop()
		if !ok {
			t.Fatalf("pop %d: queue empty", i)
		}
		if m.HTTP.Body[0] != byte(i) {
			t.Fatalf("pop %d: got %d, want %d — order not preserved", i, m.HTTP.Body[0], i)
		}
	}
	if _, ok := q.pop(); ok {
		t.Fatal("queue should be empty")
	}
	if q.bytes != 0 {
		t.Fatalf("bytes=%d after draining, want 0", q.bytes)
	}
	if q.overflowed() {
		t.Fatal("queue should not have overflowed")
	}
}

func TestMsgQueue_NeverDropsWithinCap(t *testing.T) {
	// 1000 messages of 1 KiB — far beyond the old 16-message channel buffer.
	q := newMsgQueue(2 << 20)
	body := make([]byte, 1024)
	for i := 0; i < 1000; i++ {
		q.push(chunkMsg(body))
	}
	n := 0
	for {
		if _, ok := q.pop(); !ok {
			break
		}
		n++
	}
	if n != 1000 {
		t.Fatalf("popped %d messages, want 1000 — chunks were dropped", n)
	}
}

func TestMsgQueue_OverflowFlipsAndDiscards(t *testing.T) {
	// Cap fits one message (body + msgOverheadBytes) but not two.
	q := newMsgQueue(msgOverheadBytes + 50)

	q.push(chunkMsg([]byte("12345")))  // fits
	q.push(chunkMsg([]byte("678901"))) // second message overflows
	if !q.overflowed() {
		t.Fatal("queue should have overflowed")
	}
	// Post-overflow pushes are discarded.
	q.push(chunkMsg([]byte("x")))

	m, ok := q.pop()
	if !ok || string(m.HTTP.Body) != "12345" {
		t.Fatalf("pre-overflow item should still pop; got ok=%v", ok)
	}
	if _, ok := q.pop(); ok {
		t.Fatal("overflowing and post-overflow items must not be queued")
	}
}

func TestMsgQueue_PumpDeliversInOrderThenStops(t *testing.T) {
	q := newMsgQueue(1 << 20)
	out := make(chan *common.Message, 4)
	stop := make(chan struct{})
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		q.pump(context.Background(), stop, out)
	}()

	for i := 0; i < 100; i++ {
		q.push(chunkMsg([]byte{byte(i)}))
	}
	for i := 0; i < 100; i++ {
		select {
		case m := <-out:
			if m.HTTP.Body[0] != byte(i) {
				t.Fatalf("chunk %d: got %d — out of order", i, m.HTTP.Body[0])
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("pump stalled at chunk %d", i)
		}
	}

	close(stop)
	select {
	case <-pumpDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not exit after stop")
	}
}

func TestMsgQueue_PumpEmitsOverflowSentinel(t *testing.T) {
	q := newMsgQueue(msgOverheadBytes + 4) // exactly one 4-byte message
	out := make(chan *common.Message, 8)
	stop := make(chan struct{})
	defer close(stop)
	go q.pump(context.Background(), stop, out)

	q.push(chunkMsg([]byte("abcd"))) // fills the cap exactly
	q.push(chunkMsg([]byte("e")))    // overflow

	var got []*common.Message
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case m := <-out:
			got = append(got, m)
		case <-deadline:
			t.Fatalf("received %d messages, want data + overflow sentinel", len(got))
		}
	}
	if string(got[0].HTTP.Body) != "abcd" {
		t.Fatalf("first message body=%q, want pre-overflow data", got[0].HTTP.Body)
	}
	if got[1].Error == "" {
		t.Fatal("second message should be the overflow sentinel carrying Error")
	}
}

// TestMsgQueue_CompactsBackingArray verifies that sustained push/pop traffic
// does not grow the backing array with total throughput (the items=items[1:]
// re-slice pattern would retain a slot for every message ever pushed), and
// that draining releases the array entirely.
func TestMsgQueue_CompactsBackingArray(t *testing.T) {
	q := newMsgQueue(1 << 20)
	body := []byte("x")

	for i := 0; i < 10_000; i++ {
		q.push(chunkMsg(body))
		q.push(chunkMsg(body))
		if _, ok := q.pop(); !ok {
			t.Fatalf("iteration %d: pop failed", i)
		}
		if _, ok := q.pop(); !ok {
			t.Fatalf("iteration %d: second pop failed", i)
		}
	}

	q.mu.Lock()
	itemsNil, head, capacity := q.items == nil, q.head, cap(q.items)
	q.mu.Unlock()
	if !itemsNil {
		t.Fatalf("drained queue retains backing array: head=%d cap=%d", head, capacity)
	}

	// Steady-state with a shallow queue must keep the array shallow too.
	for i := 0; i < 10_000; i++ {
		q.push(chunkMsg(body))
		if i >= 2 {
			if _, ok := q.pop(); !ok {
				t.Fatalf("iteration %d: pop failed", i)
			}
		}
	}
	q.mu.Lock()
	capacity = cap(q.items)
	q.mu.Unlock()
	if capacity > 4096 {
		t.Fatalf("backing array grew with throughput: cap=%d for a depth-3 queue", capacity)
	}
}

// TestMsgQueue_PumpStress_NoLostWakeup hammers the producer/consumer pair to
// exercise the coalesced-signal wake-up path: every pushed item must reach
// the consumer even when pushes race with the pump draining stale tokens.
// Run with -race.
func TestMsgQueue_PumpStress_NoLostWakeup(t *testing.T) {
	const n = 5000
	q := newMsgQueue(64 << 20)
	out := make(chan *common.Message) // unbuffered: maximise interleavings
	stop := make(chan struct{})
	defer close(stop)
	go q.pump(context.Background(), stop, out)

	go func() {
		for i := 0; i < n; i++ {
			q.push(chunkMsg([]byte{byte(i), byte(i >> 8)}))
			if i%97 == 0 {
				time.Sleep(time.Microsecond) // let the queue drain to empty
			}
		}
	}()

	for i := 0; i < n; i++ {
		select {
		case m := <-out:
			got := int(m.HTTP.Body[0]) | int(m.HTTP.Body[1])<<8
			if got != i&0xffff {
				t.Fatalf("item %d: got marker %d — out of order or dropped", i, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("stalled at item %d/%d — lost wake-up", i, n)
		}
	}
}
