package main

import (
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"sync"
	"syscall/js"
)

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func getRoundMessage(msg *protocol.Message, r round.Session) (round.Message, error) {
	var content round.Content

	// there are two possible content messages
	if msg.Broadcast {
		b, ok := r.(round.BroadcastRound)
		if !ok {
			return round.Message{}, errors.New("got broadcast message when none was expected")
		}
		content = b.BroadcastContent()
	} else {
		content = r.MessageContent()
	}

	// unmarshal message
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

func verifyMessage(r round.Session, msg *protocol.Message) error {
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// verify message for round
	if err = r.VerifyMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

func expectsNormalMessage(r round.Session) bool {
	return r.MessageContent() != nil
}

func verifyBroadcastMessage(r round.Session, msg *protocol.Message) error {
	// try to convert the raw message into a round.Message
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// store the broadcast message for this round
	if err = r.(round.BroadcastRound).StoreBroadcastMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if !expectsNormalMessage(r) {
		return nil
	}

	return nil
	//// otherwise, we can try to handle the p2p message that may be stored.
	//msg = h.messages[msg.RoundNumber][msg.From]
	//if msg == nil {
	//	return nil
	//}
	//return verifyMessage(r, msg)
}

func Accept(round round.Session, msg *protocol.Message) {
	if msg.Broadcast {
		if err := verifyBroadcastMessage(round, msg); err != nil {
			panic(err)
		}
	} else {
		if err := verifyMessage(round, msg); err != nil {
			panic(err)
		}
	}
}

func RoundToProtocol(r round.Session, roundMsg *round.Message) *protocol.Message {
	data, err := cbor.Marshal(roundMsg.Content)
	if err != nil {
		panic(fmt.Errorf("failed to marshal round message: %w", err))
	}
	msg := &protocol.Message{
		SSID:        r.SSID(),
		From:        r.SelfID(),
		To:          roundMsg.To,
		Protocol:    r.ProtocolID(),
		RoundNumber: roundMsg.Content.RoundNumber(),
		Data:        data,
		Broadcast:   roundMsg.Broadcast,
	}
	return msg
}

func addOne() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return args[0].Int() + 1
	})
}

func run() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		fmt.Println("------------------------------------start------------------------------------")
		ids := party.IDSlice{"client-1", "server-1"}
		threshold := 1
		sessionIDUUID := uuid.New()
		sessionIDBytes, err := sessionIDUUID.MarshalBinary()
		if err != nil {
			panic(err)
		}
		clientOut := make(chan *round.Message, 5)
		serverOut := make(chan *round.Message, 5)

		pl := pool.NewPool(0)
		defer pl.TearDown()
		ClientKeygenFn := cmp.Keygen(curve.Secp256k1{}, ids[0], ids, threshold, pl)
		clientRound1, err := ClientKeygenFn(sessionIDBytes)
		if err != nil {
			panic(err)
		}
		ServerKeygenFn := cmp.Keygen(curve.Secp256k1{}, ids[1], ids, threshold, pl)
		serverRound1, err := ServerKeygenFn(sessionIDBytes)
		if err != nil {
			panic(err)
		}
		fmt.Println("client round 1")
		clientRound2, err := clientRound1.Finalize(clientOut)
		close(clientOut)
		if err != nil {
			panic(err)
		}
		// APICall 1: Client calls server. Server starts round 1 and processes client message.
		fmt.Println("server round 1")
		serverRound2, err := serverRound1.Finalize(serverOut)
		close(serverOut)
		if err != nil {
			panic(err)
		}
		fmt.Println("server round 2 accept")
		for roundMsg := range clientOut {
			msg := RoundToProtocol(clientRound2, roundMsg)
			Accept(serverRound2, msg)
		}
		// Server returns

		// Client continues
		fmt.Println("client round 2 accept")
		for roundMsg := range serverOut {
			msg := RoundToProtocol(serverRound2, roundMsg)
			Accept(clientRound2, msg)
		}
		fmt.Println("client round 2")
		clientOut = make(chan *round.Message, 5)
		serverOut = make(chan *round.Message, 5)
		clientRound3, err := clientRound2.Finalize(clientOut)
		close(clientOut)
		if err != nil {
			panic(err)
		}

		// APICall 2: Client calls server
		fmt.Println("server round 2")
		serverRound3, err := serverRound2.Finalize(serverOut)
		close(serverOut)
		if err != nil {
			panic(err)
		}
		fmt.Println("server round 3 accept")
		for roundMsg := range clientOut {
			msg := RoundToProtocol(clientRound3, roundMsg)
			Accept(serverRound3, msg)
		}
		// Server returns

		// Client continues
		fmt.Println("client round 3 accept")
		for roundMsg := range serverOut {
			msg := RoundToProtocol(serverRound3, roundMsg)
			Accept(clientRound3, msg)
		}
		fmt.Println("client round 3")
		clientOut = make(chan *round.Message, 5)
		serverOut = make(chan *round.Message, 5)
		clientRound4, err := clientRound3.Finalize(clientOut)
		close(clientOut)
		if err != nil {
			panic(err)
		}

		// API Call 3
		fmt.Println("server round 4")
		serverRound4, err := serverRound3.Finalize(serverOut)
		close(serverOut)
		if err != nil {
			panic(err)
		}
		fmt.Println("server round 4 accept")
		for roundMsg := range clientOut {
			msg := RoundToProtocol(clientRound4, roundMsg)
			Accept(serverRound4, msg)
		}
		// Server Returns

		// Client continues
		fmt.Println("client round 4 accept")
		for roundMsg := range serverOut {
			msg := RoundToProtocol(serverRound4, roundMsg)
			Accept(clientRound4, msg)
		}
		fmt.Println("client round 4")
		clientOut = make(chan *round.Message, 2)
		serverOut = make(chan *round.Message, 2)
		clientRound5, err := clientRound4.Finalize(clientOut)
		close(clientOut)
		if err != nil {
			panic(err)
		}

		// API Call 5
		serverRound5, err := serverRound4.Finalize(serverOut)
		close(serverOut)
		if err != nil {
			panic(err)
		}
		for roundMsg := range clientOut {
			msg := RoundToProtocol(clientRound5, roundMsg)
			Accept(serverRound5, msg)
		}
		// Server Returns

		// Client continues
		for roundMsg := range serverOut {
			msg := RoundToProtocol(serverRound5, roundMsg)
			Accept(clientRound5, msg)
		}
		fmt.Println("client round 5")
		clientOut = make(chan *round.Message, 2)
		serverOut = make(chan *round.Message, 2)
		clientResultAsSession, err := clientRound5.Finalize(clientOut)
		close(clientOut)
		if err != nil {
			panic(err)
		}
		clientOutput := clientResultAsSession.(*round.Output)
		clientResult := clientOutput.Result
		clientConfig := clientResult.(*cmp.Config)
		fmt.Println(clientConfig)

		serverResultAsSession, err := serverRound5.Finalize(serverOut)
		close(serverOut)
		if err != nil {
			panic(err)
		}
		serverOutput := serverResultAsSession.(*round.Output)
		serverResult := serverOutput.Result
		serverConfig := serverResult.(*cmp.Config)
		fmt.Println(serverConfig)

		fmt.Println("------------------------------------end------------------------------------")

		fmt.Println("start signature")
		message := []byte("hello")
		net := test.NewNetwork(ids)
		configs := []*cmp.Config{clientConfig, serverConfig}
		var wg sync.WaitGroup
		for _, config := range configs {
			wg.Add(1)
			go func(config *cmp.Config) {
				goPl := pool.NewPool(1)
				defer goPl.TearDown()
				if err = CMPSign(config, message, ids, net, goPl); err != nil {
					fmt.Println(err)
				}
			}(config)
		}
		wg.Wait()
		return nil
	})
}

func main() {
	ch := make(chan struct{}, 0)
	fmt.Println("Hello, World!")
	js.Global().Set("AddOne", addOne())
	js.Global().Set("Run", run())
	<-ch
	fmt.Println("Exiting Go!")
}
