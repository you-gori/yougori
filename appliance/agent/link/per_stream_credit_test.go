package link

// Per-stream windows on the ingress and egress channels (protocol version 3; the host's
// link tests prove the same of link.rs).

import (
	"bytes"
	"testing"
)

// egressPair is a handshaken pair with guest-opened egress streams the host accepted.
func egressPair(t *testing.T, limits Limits, ids ...uint32) *pair {
	t.Helper()
	clock := newClock()
	host, err := NewHostEndpoint(testBinding(3), testNonce, limits, clock)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := NewGuestEndpoint(testBinding(3), limits, clock)
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{clock: clock, host: host, guest: guest, nonce: testNonce}
	p.handshake()
	for _, id := range ids {
		if err := p.guest.Send(OpenEgress{Stream: id, Destination: "web"}); err != nil {
			t.Fatal(err)
		}
		p.pump()
		if err := p.host.Send(Opened{Chan: ChannelEgress, Stream: id}); err != nil {
			t.Fatal(err)
		}
		p.pump()
	}
	return p
}

// sendWithin sends up to n bytes from one end on egress stream id within that stream's
// credit; how many went.
func sendWithin(t *testing.T, from *Endpoint, id uint32, n int) int {
	t.Helper()
	sent := 0
	for sent < n {
		chunk := n - sent
		if max := from.MaxDataBytes(ChannelEgress); chunk > max {
			chunk = max
		}
		if credit := from.StreamSendCredit(ChannelEgress, id); uint64(chunk) > credit {
			chunk = int(credit)
		}
		if chunk == 0 {
			break
		}
		if err := from.Send(Data{Chan: ChannelEgress, Stream: id, Bytes: bytes.Repeat([]byte{5}, chunk)}); err != nil {
			t.Fatal(err)
		}
		sent += chunk
	}
	return sent
}

func streamCredits(events []Event) map[uint32]uint32 {
	credits := map[uint32]uint32{}
	for _, m := range messagesOf(events) {
		if update, ok := m.(StreamWindowUpdate); ok {
			credits[update.Stream] += update.CreditBytes
		}
	}
	return credits
}

// PROVES one stream whose reader stopped holds back no other, either way: the guest's
// stream 1 takes its whole first window and the host never consumes it, the host's
// stream 1 likewise to the guest, and stream 3 still carries 1 MiB each way as each end
// consumes it, credited alone.
func TestAStalledStreamHoldsBackNoOtherStream(t *testing.T) {
	p := egressPair(t, DefaultLimits(), 1, 3)
	if sent := sendWithin(t, p.guest, 1, 1<<20); sent != int(StreamWindowBytes) {
		t.Fatalf("the guest sent %d bytes on a fresh stream", sent)
	}
	if sent := sendWithin(t, p.host, 1, 1<<20); sent != int(StreamWindowBytes) {
		t.Fatalf("the host sent %d bytes on a fresh stream", sent)
	}
	p.pump()
	if err := p.guest.Send(Data{Chan: ChannelEgress, Stream: 1, Bytes: []byte("x")}); err == nil || err.(*SendRefusal).Code != "no_stream_credit" {
		t.Fatalf("a send past the stream's window: %v", err)
	}
	for carried := 0; carried < 1<<20; carried += 16384 {
		if sent := sendWithin(t, p.guest, 3, 16384); sent != 16384 {
			t.Fatalf("stream 3 sent %d up beside the stalled stream", sent)
		}
		if sent := sendWithin(t, p.host, 3, 16384); sent != 16384 {
			t.Fatalf("stream 3 sent %d down beside the stalled stream", sent)
		}
		p.pump()
		if err := p.host.ConsumeStream(ChannelEgress, 3, 16384); err != nil {
			t.Fatal(err)
		}
		if err := p.guest.ConsumeStream(ChannelEgress, 3, 16384); err != nil {
			t.Fatal(err)
		}
		hostEvents, guestEvents := p.pump()
		for _, events := range [][]Event{hostEvents, guestEvents} {
			for id := range streamCredits(events) {
				if id != 3 {
					t.Fatalf("stream %d was credited", id)
				}
			}
		}
	}
	if held := p.host.Channel(ChannelEgress).Buffered; held != StreamWindowBytes {
		t.Fatalf("the host holds %d bytes", held)
	}
	if held := p.guest.Channel(ChannelEgress).Buffered; held != StreamWindowBytes {
		t.Fatalf("the guest holds %d bytes", held)
	}
}

// PROVES a receiver may grant a stream its grown window as it opens, within the channel's
// growth quota: the first two streams grow, the third keeps its first window until a grown
// one ends, and a stream that is not open is refused.
func TestGrowStreamGrantsTheGrownWindowWithinTheQuota(t *testing.T) {
	limits := DefaultLimits()
	limits.Egress.MaxBufferedBytes = 2 * (MaxStreamWindowBytes - StreamWindowBytes)
	p := egressPair(t, limits, 1, 3, 5)
	for _, id := range []uint32{1, 3, 5} {
		if err := p.guest.GrowStream(ChannelEgress, id); err != nil {
			t.Fatal(err)
		}
	}
	hostEvents, _ := p.pump()
	credits := streamCredits(hostEvents)
	grown := uint32(MaxStreamWindowBytes - StreamWindowBytes)
	if credits[1] != grown || credits[3] != grown || credits[5] != 0 {
		t.Fatalf("credits %v", credits)
	}
	if credit := p.host.StreamSendCredit(ChannelEgress, 1); credit != MaxStreamWindowBytes {
		t.Fatalf("the host may send %d on a grown stream", credit)
	}
	_ = p.guest.Send(Cancel{Chan: ChannelEgress, Stream: 1, Cause: CancelRequested})
	p.pump()
	_ = p.guest.GrowStream(ChannelEgress, 5)
	hostEvents, _ = p.pump()
	if streamCredits(hostEvents)[5] != grown {
		t.Fatalf("stream 5 did not grow once stream 1's growth came back: %v", streamCredits(hostEvents))
	}
	if err := p.guest.GrowStream(ChannelEgress, 9); err == nil {
		t.Fatal("a stream that is not open grew")
	}
}

// PROVES a peer that sends past a stream's window closes the channel and the link stays up.
func TestDataBeyondAStreamsWindowClosesTheChannel(t *testing.T) {
	p := egressPair(t, DefaultLimits(), 1)
	sendWithin(t, p.host, 1, int(StreamWindowBytes))
	p.pump()
	// An authentic frame the host's own accounting would not let out.
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, Data{Chan: ChannelEgress, Stream: 1, Bytes: []byte("x")})
	codes := refusalCodes(p.guest.Receive(frame))
	if len(codes) != 1 || codes[0] != ReasonStreamWindowExceeded || !p.guest.Channel(ChannelEgress).Closed || p.guest.IsClosed() {
		t.Fatalf("%v", codes)
	}
	if err := p.guest.Consume(ChannelEgress, 1); err == nil || err.(*SendRefusal).Code != "per_stream" {
		t.Fatalf("channel credit on egress: %v", err)
	}
	if err := p.guest.Grant(ChannelIngress, 1); err == nil || err.(*SendRefusal).Code != "per_stream" {
		t.Fatalf("a channel grant on ingress: %v", err)
	}
	if err := p.guest.ConsumeStream(ChannelTerminal, 2, 1); err == nil || err.(*SendRefusal).Code != "not_per_stream" {
		t.Fatalf("stream credit on the terminal channel: %v", err)
	}
}

// PROVES a stream is credited once a quarter of its window is due, grows once it consumed a
// whole first window, the channel's growth stays within its quota (a stream past it keeps
// its first window), and a stream's growth comes back when it ends; credit that crosses a
// stream's finish is dropped quietly.
func TestFastStreamsGrowWithinTheChannelsQuota(t *testing.T) {
	limits := DefaultLimits()
	limits.Egress.MaxBufferedBytes = 2 * (MaxStreamWindowBytes - StreamWindowBytes)
	p := egressPair(t, limits, 1, 3, 5)
	sendWithin(t, p.guest, 1, 10000)
	p.pump()
	if err := p.host.ConsumeStream(ChannelEgress, 1, 10001); err == nil {
		t.Fatal("more consumed than held")
	}
	_ = p.host.ConsumeStream(ChannelEgress, 1, 10000)
	if _, guestEvents := p.pump(); len(streamCredits(guestEvents)) != 0 {
		t.Fatal("credit before a quarter of the window was due")
	}
	sendWithin(t, p.guest, 1, int(StreamWindowBytes)-10000)
	p.pump()
	_ = p.host.ConsumeStream(ChannelEgress, 1, uint32(StreamWindowBytes)-10000)
	if _, guestEvents := p.pump(); streamCredits(guestEvents)[1] != uint32(MaxStreamWindowBytes) {
		t.Fatalf("credit %v after a whole first window", streamCredits(guestEvents))
	}
	var guestEvents []Event
	for _, id := range []uint32{3, 5} {
		sendWithin(t, p.guest, id, int(StreamWindowBytes))
		_, events := p.pump()
		guestEvents = append(guestEvents, events...)
		_ = p.host.ConsumeStream(ChannelEgress, id, uint32(StreamWindowBytes))
	}
	_, events := p.pump()
	guestEvents = append(guestEvents, events...)
	if credits := streamCredits(guestEvents); credits[3] != uint32(MaxStreamWindowBytes) || credits[5] != uint32(StreamWindowBytes) {
		t.Fatalf("credits %v: the third stream past the quota keeps its first window", credits)
	}
	if err := p.host.Send(Cancel{Chan: ChannelEgress, Stream: 1, Cause: CancelRequested}); err != nil {
		t.Fatal(err)
	}
	p.pump()
	sendWithin(t, p.guest, 5, 20000)
	p.pump()
	_ = p.host.ConsumeStream(ChannelEgress, 5, 20000)
	if _, guestEvents := p.pump(); streamCredits(guestEvents)[5] != uint32(MaxStreamWindowBytes-StreamWindowBytes+20000) {
		t.Fatalf("credit %v after stream 1's growth came back", streamCredits(guestEvents))
	}
	// Both ends finish stream 3; credit for it crosses the finish and is dropped quietly.
	_ = p.host.Send(EndOfStream{Chan: ChannelEgress, Stream: 3})
	_ = p.guest.Send(EndOfStream{Chan: ChannelEgress, Stream: 3})
	p.pump()
	frame, _ := p.guest.Binding().EncodeFrame(SenderGuest, p.nonce, p.host.LastReceivedSequence()+1, StreamWindowUpdate{Chan: ChannelEgress, Stream: 3, CreditBytes: 1})
	if events := p.host.Receive(frame); len(events) != 0 {
		t.Fatalf("credit across the finish: %v", events)
	}
}
