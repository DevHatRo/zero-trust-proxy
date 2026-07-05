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
	q := newMsgQueue(10) // 10-byte cap

	q.push(chunkMsg([]byte("12345")))  // 5 bytes — fits
	q.push(chunkMsg([]byte("678901"))) // 11 total — overflow
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
	q := newMsgQueue(4)
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
