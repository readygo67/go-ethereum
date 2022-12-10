package dawn

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestValidatorSetSort(t *testing.T) {
	size := 100
	validators := make([]common.Address, size)
	for i := 0; i < size; i++ {
		validators[i] = randomAddress()
	}
	sort.Sort(validatorsAscending(validators))
	for i := 0; i < size-1; i++ {
		assert.True(t, bytes.Compare(validators[i][:], validators[i+1][:]) < 0)
	}
}

func TestStoreAndLoadSnapshot(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	dawnConfig := params.DawnConfig{
		Period: 2,
		Epoch:  1000,
	}
	signatures, _ := lru.NewARC(100)
	hash := randomHash()
	validators := []common.Address{
		randomAddress(),
		randomAddress(),
		randomAddress(),
	}
	snap := newSnapshot(&dawnConfig, signatures, 10, hash, validators)

	snap.store(db)
	newSnap, err := loadSnapshot(&dawnConfig, signatures, db, hash)
	require.NoError(t, err)
	require.Equal(t, snap.Hash, newSnap.Hash)
	require.Equal(t, snap.Number, newSnap.Number)

	validators = snap.validators()
	sort.Sort(validatorsAscending(validators))

	newValidators := newSnap.validators()
	sort.Sort(validatorsAscending(newValidators))
	require.Equal(t, validators, newValidators)
}

// in TestSnapshotApply. 10 validators are divided into 2 set, validator[:5] for block <=10, validator[5:] for block >=11.
// block10 (epoch1's first block) is produced by last epoch's first validator(i.e. validator0), meanwhile in the block10's header
// epoch1's validator set are carried. this schema make sense, epoch0's first block is produced by validator1.
func TestSnapshotApply(t *testing.T) {
	//block9's signer = validator[4]
	//block10's signer = validator[0],
	validatorLen := 10
	chainId := big.NewInt(100)
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

	//snap8
	snap8 := newSnapshot(&dawnConfig, signatures, 8, header8Hash, validators[:5])
	require.Equal(t, validators[:5], snap8.validators())

	//snap9 = snap8+header9
	blockNumber := int64(9)
	signValidatorIndex := 4
	extra9 := bytes.Repeat([]byte{0x00}, extraVanity)
	extra9 = append(extra9, make([]byte, extraSeal)...)
	header9 := &types.Header{
		ParentHash:  header8Hash,
		UncleHash:   common.Hash{},
		Coinbase:    validators[signValidatorIndex],
		Root:        randomHash(),
		TxHash:      randomHash(),
		ReceiptHash: randomHash(),
		Difficulty:  diffInTurn,
		Number:      big.NewInt(blockNumber),
		GasLimit:    params.GenesisGasLimit,
		GasUsed:     0,
		Time:        uint64(time.Now().Unix()),
		Extra:       extra9,
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
	}

	header9Hash := SealHash(header9, chainId)
	header9Sig, err := crypto.Sign(header9Hash.Bytes(), privates[signValidatorIndex])
	require.NoError(t, err)

	copy(header9.Extra[len(header9.Extra)-extraSeal:], header9Sig)
	snap9, err := snap8.apply([]*types.Header{header9}, chainId)
	require.NoError(t, err)

	require.EqualValues(t, 9, snap9.Number)
	require.Equal(t, header9.Hash(), snap9.Hash)

	//snap10 = snap9+header10
	time.Sleep(time.Duration(snap9.config.Period) * time.Second)
	blockNumber = int64(10)
	signValidatorIndex = 0
	extra10 := bytes.Repeat([]byte{0x00}, extraVanity)
	for _, validator := range validators[5:] {
		extra10 = append(extra10, validator.Bytes()...)
	}
	extra10 = append(extra10, make([]byte, extraSeal)...)

	header10 := &types.Header{
		ParentHash:  header9.Hash(),
		UncleHash:   common.Hash{},
		Coinbase:    validators[signValidatorIndex],
		Root:        randomHash(),
		TxHash:      randomHash(),
		ReceiptHash: randomHash(),
		Difficulty:  diffInTurn,
		Number:      big.NewInt(blockNumber),
		GasLimit:    params.GenesisGasLimit,
		GasUsed:     0,
		Time:        uint64(time.Now().Unix()),
		Extra:       extra10,
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
	}

	header10SigHash := SealHash(header10, chainId)
	header10Sig, err := crypto.Sign(header10SigHash.Bytes(), privates[signValidatorIndex])
	require.NoError(t, err)
	copy(header10.Extra[len(header10.Extra)-extraSeal:], header10Sig)

	snap10, err := snap9.apply([]*types.Header{header10}, chainId)
	require.NoError(t, err)
	require.EqualValues(t, blockNumber, snap10.Number)
	require.Equal(t, header10.Hash(), snap10.Hash)
	require.Equal(t, validators[5:], snap10.validators())

	//snap11 = snap10+header11
	time.Sleep(time.Duration(snap10.config.Period) * time.Second)
	blockNumber = 11
	signValidatorIndex = 6
	extra11 := bytes.Repeat([]byte{0x00}, extraVanity)
	extra11 = append(extra11, make([]byte, extraSeal)...)

	header11 := &types.Header{
		ParentHash:  header10.Hash(),
		UncleHash:   common.Hash{},
		Coinbase:    validators[signValidatorIndex],
		Root:        randomHash(),
		TxHash:      randomHash(),
		ReceiptHash: randomHash(),
		Difficulty:  diffInTurn,
		Number:      big.NewInt(blockNumber),
		GasLimit:    params.GenesisGasLimit,
		GasUsed:     0,
		Time:        uint64(time.Now().Unix()),
		Extra:       extra10,
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
	}

	header11SigHash := SealHash(header11, chainId)
	header11Sig, err := crypto.Sign(header11SigHash.Bytes(), privates[signValidatorIndex])
	require.NoError(t, err)
	copy(header11.Extra[len(header11.Extra)-extraSeal:], header11Sig)

	snap11, err := snap10.apply([]*types.Header{header11}, chainId)
	require.NoError(t, err)
	require.EqualValues(t, blockNumber, snap11.Number)
	require.Equal(t, header11.Hash(), snap11.Hash)
	require.Equal(t, validators[5:], snap11.validators())
}

func TestMapLength(t *testing.T) {
	recents := make(map[uint]struct{}, 0)
	recents[0] = struct{}{}
	recents[1] = struct{}{}
	require.Equal(t, 2, len(recents))
}

func randomAddress() common.Address {
	addrBytes := make([]byte, 20)
	rand.Read(addrBytes)
	return common.BytesToAddress(addrBytes)
}

func randomHash() common.Hash {
	hashBytes := make([]byte, 32)
	rand.Read(hashBytes)
	return common.BytesToHash(hashBytes)
}
