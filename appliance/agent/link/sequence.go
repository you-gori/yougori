package link

// Monotonically checked sequence state, one per direction (host:
// src-tauri/src/sandbox/link/sequence.rs). Sequences start at 1 and rise by exactly one
// per frame; a repeated or lower sequence is a replay and a higher one a reorder or gap.

import (
	"fmt"
	"math"
)

// SequenceKind names a sequence refusal.
type SequenceKind uint8

const (
	SequenceReplayed SequenceKind = iota + 1
	SequenceReordered
	SequenceExhausted
)

// SequenceRefusal is why a sequence was refused.
type SequenceRefusal struct {
	Kind         SequenceKind
	Sequence     uint64
	LastAccepted uint64
	Expected     uint64
}

// Code is the stable name used by the conformance corpus.
func (r *SequenceRefusal) Code() string {
	switch r.Kind {
	case SequenceReplayed:
		return "sequence.replayed"
	case SequenceReordered:
		return "sequence.reordered"
	}
	return "sequence.exhausted"
}

func (r *SequenceRefusal) Error() string {
	switch r.Kind {
	case SequenceReplayed:
		return fmt.Sprintf("sequence %d was already passed; the last accepted is %d", r.Sequence, r.LastAccepted)
	case SequenceReordered:
		return fmt.Sprintf("sequence %d arrived where %d was expected", r.Sequence, r.Expected)
	}
	return "the sequence space of this direction is used up"
}

// SequenceState is the sequence state of one direction.
type SequenceState struct {
	lastAccepted uint64
}

// LastAccepted is the last sequence accepted or sent.
func (s *SequenceState) LastAccepted() uint64 { return s.lastAccepted }

// Accept accepts sequence only when it is exactly the next one.
func (s *SequenceState) Accept(sequence uint64) *SequenceRefusal {
	if s.lastAccepted == math.MaxUint64 {
		return &SequenceRefusal{Kind: SequenceExhausted}
	}
	expected := s.lastAccepted + 1
	if sequence <= s.lastAccepted {
		return &SequenceRefusal{Kind: SequenceReplayed, Sequence: sequence, LastAccepted: s.lastAccepted}
	}
	if sequence != expected {
		return &SequenceRefusal{Kind: SequenceReordered, Sequence: sequence, Expected: expected}
	}
	s.lastAccepted = sequence
	return nil
}

// NextForSend takes the next sequence for a frame this side sends.
func (s *SequenceState) NextForSend() (uint64, *SequenceRefusal) {
	if s.lastAccepted == math.MaxUint64 {
		return 0, &SequenceRefusal{Kind: SequenceExhausted}
	}
	s.lastAccepted++
	return s.lastAccepted, nil
}
