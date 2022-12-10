package dawn

import (
	"bytes"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
	"math/big"
	"sort"
	"time"
)

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.DawnConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache      // Cache of recent block signatures to speed up ecrecover

	Number     uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Validators map[common.Address]struct{} `json:"validators"` // Set of authorized validators at this moment
	Recents    map[uint64]common.Address   `json:"recents"`    // Set of recent validators for spam protections  //@keep，这个“最近”的定义是最新的len(Snapshot.Validators)/2 + 1个块
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type validatorsAscending []common.Address

func (s validatorsAscending) Len() int           { return len(s) }
func (s validatorsAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s validatorsAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// method does not initialize the set of recent validators, so only ever use if for
// the genesis block.
func newSnapshot(config *params.DawnConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, validators []common.Address) *Snapshot {
	snap := &Snapshot{
		config:     config,
		sigcache:   sigcache,
		Number:     number,
		Hash:       hash,
		Validators: make(map[common.Address]struct{}),
		Recents:    make(map[uint64]common.Address),
	}
	for _, validator := range validators {
		snap.Validators[validator] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.DawnConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("dawn-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("dawn-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:     s.config,
		sigcache:   s.sigcache,
		Number:     s.Number,
		Hash:       s.Hash,
		Validators: make(map[common.Address]struct{}),
		Recents:    make(map[uint64]common.Address),
	}
	for validator := range s.Validators {
		cpy.Validators[validator] = struct{}{}
	}
	for block, validator := range s.Recents {
		cpy.Recents[block] = validator
	}
	return cpy
}

func (s *Snapshot) apply(headers []*types.Header, chainId *big.Int) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	//@keep，检查headers应该按照高度从小到达排序，
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errNotContinuousBlockNumber
		}
	}
	//snapshot[i-1] 加上header[i] => 生产出snapshot[i]
	//@keep，检查基准的snap和第一个header是否是连续的。
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errNotContinuousBlockNumber
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for m, header := range headers {
		number := header.Number.Uint64()
		// Delete the oldest validator from the recent list to allow it signing again
		if limit := uint64(len(snap.validators())/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against validators
		validator, err := ecrecover(header, s.sigcache, chainId)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Validators[validator]; !ok {
			return nil, errUnauthorizedValidator
		}
		for _, recent := range snap.Recents {
			if recent == validator {
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = validator

		if number > 0 && number%s.config.Epoch == 0 {
			//@keep，理论上不会header是不会跨epoch的，但是为了兼容这种情况，此处做容错处理
			log.Warn("snapshot apply, Cross epoch situation happen, need check", "snap", s, "headers", headers)
			for k, _ := range snap.Recents {
				delete(snap.Recents, k)
			}

			for v, _ := range s.Validators {
				delete(snap.Validators, v)
			}

			//从epoch header中取出signers列表
			newValidators := make([]common.Address, (len(header.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(newValidators); i++ {
				//copy出signer的列表
				copy(newValidators[i][:], header.Extra[extraVanity+i*common.AddressLength:])
			}

			for _, v := range newValidators {
				snap.Validators[v] = struct{}{}
			}
		}

		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing snapshot history", "processed", m, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}

	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed snapshot history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// validators retrieves the list of authorized validators in ascending order.
// @keep，validators 按照地址的bytes 大小排序。
func (s *Snapshot) validators() []common.Address {
	sigs := make([]common.Address, 0, len(s.Validators))
	for sig := range s.Validators {
		sigs = append(sigs, sig)
	}
	sort.Sort(validatorsAscending(sigs))
	return sigs
}

// @keep，使用区块高度来决定是否为inturn，还是outturn
// inturn returns if a validator at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, validator common.Address) bool {
	validators := s.validators()
	offset := number % uint64(len(validators))
	return validators[offset] == validator
}

func (s *Snapshot) indexOfValidator(validator common.Address) int {
	validators := s.validators()
	for i, v := range validators {
		if v == validator {
			return i
		}
	}
	return -1
}

func (s *Snapshot) validatorInTurn() common.Address {
	validators := s.validators()
	index := (s.Number + 1) % uint64(len(validators))
	return validators[index]
}
