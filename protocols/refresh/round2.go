package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round2 struct {
	*round1
	// EchoHash = Hash(SSID, commitment₁, …, commitmentₙ)
	EchoHash []byte
}

// ProcessMessage implements round.Round
//
// - store commitment Vⱼ
func (r *round2) ProcessMessage(from party.ID, content round.Content) error {
	body := content.(*Keygen2)
	partyJ := r.Parties[from]

	partyJ.Commitment = body.Commitment
	return nil
}

// GenerateMessages implements round.Round
//
// Since we assume a simple P2P network, we use an extra round to "echo"
// the hash. Everybody sends a hash of all hashes.
//
// - send Hash(ssid, V₁, …, Vₙ)
func (r *round2) GenerateMessages(out chan<- *round.Message) error {
	// Broadcast the message we created in round1
	h := r.Hash()
	for _, partyID := range r.PartyIDs() {
		_, _ = h.WriteAny(r.Parties[partyID].Commitment)
	}
	echoHash := h.ReadBytes(nil)

	// send to all
	msg := r.MarshalMessage(&Keygen3{HashEcho: echoHash}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return err
	}

	r.EchoHash = echoHash
	return nil
}

// Next implements round.Round
func (r *round2) Next() round.Round {
	return &round3{
		round2: r,
	}
}

func (r *round2) MessageContent() round.Content {
	return &Keygen2{}
}

func (m *Keygen2) Validate() error {
	if m == nil {
		return errors.New("keygen.round1: message is nil")
	}
	if l := len(m.Commitment); l != params.HashBytes {
		return fmt.Errorf("keygen.round1: invalid commitment length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

func (m *Keygen2) RoundNumber() types.RoundNumber {
	return 2
}
