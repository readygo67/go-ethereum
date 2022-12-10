package dawn

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBackoffTime(t *testing.T) {
	//block9's signer = validator[4]
	//block10's signer = validator[0],
	validatorLen := 10
	dawnConfig := params.DawnConfig{
		Period: 2,
		Epoch:  10,
	}
	signatures, _ := lru.NewARC(100)
	header8Hash := randomHash()

	privates := make([]*ecdsa.PrivateKey, validatorLen)
	validators := make([]common.Address, validatorLen)

	for i := 0; i < validatorLen; i++ {
		key, _ := crypto.GenerateKey()
		privates[i] = key

		addr := crypto.PubkeyToAddress(key.PublicKey)
		validators[i] = addr
	}

	//sorting the validators and they privatekeys
	for i := 0; i < len(validators)-1; i++ {
		for j := i + 1; j < len(validators); j++ {
			if bytes.Compare(validators[i][:], validators[j][:]) > 0 {
				validators[i], validators[j] = validators[j], validators[i]
				privates[i], privates[j] = privates[j], privates[i]
			}
		}
	}

	for h := uint64(1); h < 10; h++ {
		snap := newSnapshot(&dawnConfig, signatures, h, header8Hash, validators[:5])

		delay := make([]uint64, 5)
		//fmt.Printf("h:%v", h)
		for i := 0; i < 5; i++ {
			delay[i] = backOffTime(snap, validators[i])
			//fmt.Printf("delay[%v]=%v  ", i, delay[i])
		}
		//fmt.Printf("\n")
		for i := 0; i < 4; i++ {
			for j := i + 1; j < 5; j++ {
				require.NotEqual(t, delay[i], delay[j])
			}
		}
	}

}
