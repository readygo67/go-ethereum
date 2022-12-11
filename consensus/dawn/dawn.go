package dawn

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"io"
	"sort"

	"github.com/ethereum/go-ethereum/consensus/dawn/systemcontracts"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
	"math/big"
	"sync"
	"time"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	wiggleTime         = uint64(1) // Random delay (per signer) to allow concurrent signers
	initialBackOffTime = uint64(1) // second
	processBackOffTime = uint64(1) // second

	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	maxValidators = 21 // Max validators allowed to seal.
)

// Clique proof-of-authority protocol constants.
var (
	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures， InTurn 难度为2，NoTurn难度为1
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures

	systemContracts = map[common.Address]bool{
		common.HexToAddress(systemcontracts.Validators):  true,
		common.HexToAddress(systemcontracts.Slasher):     true,
		common.HexToAddress(systemcontracts.Governor):    true,
		common.HexToAddress(systemcontracts.Timelocker):  true,
		common.HexToAddress(systemcontracts.Commissions): true,
	}
)

var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")
	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// invalid list of validators (i.e. non divisible by 20 bytes).
	errNotContinuousBlockNumber = errors.New("not continuous block number")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingEpochValidators = errors.New("mismatching validators list on epoch block")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")

	// errInvalidValidatorLen is returned if validators length is zero or bigger than maxValidators.
	errInvalidValidatorsNumber = errors.New("Invalid validators number")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
type SignerTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)

type Dawn struct {
	chainConfig *params.ChainConfig
	config      *params.DawnConfig // Consensus engine configuration parameters
	db          ethdb.Database     // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	validator common.Address //self address
	signer    types.Signer
	signFn    SignerFn
	signTxFn  SignerTxFn
	lock      sync.RWMutex

	ethAPI         *ethapi.BlockChainAPI
	validatorsABI  abi.ABI //system contract's ABI
	slasherABI     abi.ABI
	commissionsABI abi.ABI //

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

func New(chainConfig *params.ChainConfig, db ethdb.Database) *Dawn {
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inMemorySignatures)

	// get harmony config
	dawnConfig := chainConfig.Dawn
	// Set any missing consensus parameters to their defaults
	if dawnConfig != nil && dawnConfig.Epoch == 0 {
		dawnConfig.Epoch = epochLength
	}

	//TODO(keep), init system contracts abi here

	return &Dawn{
		chainConfig: chainConfig,
		config:      dawnConfig,
		db:          db,
		signer:      types.LatestSigner(chainConfig),
		signatures:  signatures,
		recents:     recents,
	}
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var validator common.Address
	copy(validator[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, validator)
	return validator, nil
}

// @keep,判断是否为系统合约
func isToSystemContract(to common.Address) bool {
	return systemContracts[to]
}

func (d *Dawn) IsSystemTransaction(tx *types.Transaction, header *types.Header) (bool, error) {
	// deploy a contract
	if tx.To() == nil {
		return false, nil
	}
	sender, err := types.Sender(d.signer, tx)
	if err != nil {
		return false, errors.New("UnAuthorized transaction")
	}
	//@keep,系统合约的三个条件1. sender = header.coinbase,  2. to地址为系统合约的地址， 3.gasPrice = 0
	if sender == header.Coinbase && isToSystemContract(*tx.To()) && tx.GasPrice().Cmp(big.NewInt(0)) == 0 {
		return true, nil
	}
	return false, nil
}

func (d *Dawn) IsSystemContract(to *common.Address) bool {
	if to == nil {
		return false
	}
	return isToSystemContract(*to)
}

// Author implements consensus.Engine, returning the SystemAddress
func (d *Dawn) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (d *Dawn) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (d *Dawn) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (d *Dawn) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	// Unnecessary to verify the block from feature
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// check extra data
	checkpoint := (number % d.config.Epoch) == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		//@keep，如果不是epoch,  signersBytes应该为0
		return errExtraValidators
	}

	if checkpoint && signersBytes%common.AddressLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in harmony
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}

	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	return d.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (d *Dawn) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	err = d.verifyBlockTime(snap, header, parent)
	if err != nil {
		return err
	}

	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}

	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	return d.verifySeal(chain, header, parents)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (d *Dawn) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, d.signatures, d.chainConfig.ChainID)
	if err != nil {
		return err
	}

	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}

	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}

	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !d.fakeDiff {
		inturn := snap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}

	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (d *Dawn) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = d.validator
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	header.Difficulty = calcDifficulty(snap, d.validator)

	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	//@keep，准备出epoch块，
	if number%d.config.Epoch == 0 {
		newValidators, err := d.getCurrentValidators(header.ParentHash, new(big.Int).Sub(header.Number, common.Big1))
		if err != nil {
			return err
		}

		// sort validator by address
		sort.Sort(validatorsAscending(newValidators))
		for _, validator := range newValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	header.Time = d.blockTime(snap, parent)
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (d *Dawn) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs *[]*types.Transaction,
	uncles []*types.Header, receipts *[]*types.Receipt, systemTxs *[]*types.Transaction, usedGas *uint64) error {

	// avoid nil pointer
	if txs == nil {
		s := make([]*types.Transaction, 0)
		txs = &s
	}
	if receipts == nil {
		rs := make([]*types.Receipt, 0)
		receipts = &rs
	}

	number := header.Number.Uint64()
	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	if number > 0 && number%d.config.Epoch == 0 {
		newValidators, err := d.getCurrentValidators(header.ParentHash, new(big.Int).Sub(header.Number, common.Big1))
		if err != nil {
			return err
		}
		// sort validator by address
		sort.Sort(validatorsAscending(newValidators))
		validatorsBytes := make([]byte, len(newValidators)*common.AddressLength)
		for i, validator := range newValidators {
			copy(validatorsBytes[i*common.AddressLength:], validator.Bytes())
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], validatorsBytes) {
			return errMismatchingEpochValidators
		}
	}

	// Initialize all system contracts at block 1.
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	cx := chainContext{chain: chain, dawn: d}
	if number == 1 {
		if err := d.initContract(chain, state, header, cx, txs, receipts, systemTxs, usedGas, false); err != nil {
			log.Error("Initialize system contracts failed", "err", err)
			return err
		}
	}

	if header.Difficulty.Cmp(diffInTurn) != 0 {
		validatorInTurn := snap.validatorInTurn()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == validatorInTurn {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			log.Trace("slash validator", "block hash", header.Hash(), "validator", validatorInTurn)
			err = d.slash(validatorInTurn, state, header, cx, txs, receipts, systemTxs, usedGas, false)
			if err != nil {
				// it is possible that slash validator failed because of the slash channel is disabled.
				log.Error("slash validator failed", "block hash", header.Hash(), "address", validatorInTurn)
			}
		}
	}

	validator := header.Coinbase
	err = d.distributeBlockReward(validator, state, header, cx, txs, receipts, systemTxs, usedGas, false)
	if err != nil {
		return err
	}
	if len(*systemTxs) > 0 {
		//TODO(keep), Why??
		return errors.New("the length of systemTxs do not match")
	}

	return nil
}

//// @keep, ok
//func (h *Dawn) Coinbase(header *types.Header) (common.Address, error) {
//	return header.Coinbase, nil
//}

func (d *Dawn) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, []*types.Receipt, error) {

	// No block rewards in PoA, so the state remains as is and uncles are dropped
	chainCtx := chainContext{chain: chain, dawn: d}
	if txs == nil {
		txs = make([]*types.Transaction, 0)
	}
	if receipts == nil {
		receipts = make([]*types.Receipt, 0)
	}
	if header.Number.Cmp(common.Big1) == 0 {
		err := d.initContract(chain, state, header, chainCtx, &txs, &receipts, nil, &header.GasUsed, true)
		if err != nil {
			log.Error("init contract failed")
		}
	}

	if header.Difficulty.Cmp(diffInTurn) != 0 {
		number := header.Number.Uint64()
		snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
		if err != nil {
			return nil, nil, err
		}
		validatorInTurn := snap.validatorInTurn()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == validatorInTurn {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			err = d.slash(validatorInTurn, state, header, chainCtx, &txs, &receipts, nil, &header.GasUsed, true)
			if err != nil {
				// it is possible that slash validator failed because of the slash channel is disabled.
				log.Error("slash validator failed", "block hash", header.Hash(), "address", validatorInTurn)
			}
		}
	}

	err := d.distributeBlockReward(d.validator, state, header, chainCtx, &txs, &receipts, nil, &header.GasUsed, true)
	if err != nil {
		return nil, nil, err
	}
	// should not happen. Once happen, stop the node is better than broadcast the block
	if header.GasLimit < header.GasUsed {
		return nil, nil, errors.New("gas consumption of system txs exceed the gas limit")
	}

	header.UncleHash = types.CalcUncleHash(nil)
	var blk *types.Block
	var rootHash common.Hash
	wg := sync.WaitGroup{}
	wg.Add(2)
	//@keep，并行执行
	go func() {
		rootHash = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
		wg.Done()
	}()
	go func() {
		blk = types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
		wg.Done()
	}()
	wg.Wait()
	blk.SetRoot(rootHash)
	// Assemble and return the final block for sealing
	return blk, receipts, nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (d *Dawn) Authorize(validator common.Address, signFn SignerFn, signTxFn SignerTxFn) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.validator = validator
	d.signFn = signFn
	d.signTxFn = signTxFn
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (d *Dawn) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if d.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}

	// Don't hold the val fields for the entire sealing procedure
	d.lock.RLock()
	validator, signFn := d.validator, d.signFn
	d.lock.RUnlock()

	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[validator]; !authorized {
		return errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == validator {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others")
				return nil
			}
		}
	}

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := d.blockDelay(snap, header)

	log.Info("Sealing block with", "number", number, "delay", delay, "headerDifficulty", header.Difficulty, "val", validator.Hex())

	// time's up, sign the block
	sig, err := signFn(accounts.Account{Address: d.validator}, accounts.MimetypeDawn, DawnRLP(header, d.chainConfig.ChainID))
	if err != nil {
		log.Error("signFn error", "err", err)
		return nil
	}
	copy(block.Header().Extra[len(block.Header().Extra)-extraSeal:], sig)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header, d.chainConfig.ChainID))
		}
	}()

	return nil
}

func (d *Dawn) SealHash(header *types.Header) common.Hash {
	return SealHash(header, d.chainConfig.ChainID)
}

func (d *Dawn) Close() error {
	return nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
// @keep，获取指定hash的的snapshot
func (d *Dawn) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		// 首先从recents 中找
		if s, ok := d.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%d.config.Epoch == 0 {
			//如果高度为checkpointInterval的整数倍，则直接尝试从数据库中读取Snapshot对象
			if s, err := loadSnapshot(d.config, d.signatures, d.db, hash); err == nil {
				log.Trace("Loaded snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis , snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		//@keep,如果在创世块或者epoch块，直接从header中恢复出snapshot。
		if number == 0 || (number%d.config.Epoch == 0 /* && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)*/) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				//从checkpoint中取出signers列表
				signers := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					//copy出signer的列表
					copy(signers[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				//调用newSnapshot在checkpoint上创建Snapshot对象，并将其存入数据库中
				snap = newSnapshot(d.config, d.signatures, number, hash, signers)
				if err := snap.store(d.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		//如果以上情况都不是，则往前回溯区块的链，并保存回溯过程中遇到的header
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		//如果以上情况都不是，则往前回溯区块的链，并保存回溯过程中遇到的header。知道找到一个snapshot
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	// @keep， 将headers 反转，反转后按高度从小到大排序
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	//将回溯中遇到的headers传给apply方法，得到一个新的snap对象
	//@Keep，找到了之前的一个快照作为基准，然后将一路上遇到的headers 都传进去，构建一个较新的快照。
	snap, err := snap.apply(headers, d.chainConfig.ChainID)
	if err != nil {
		return nil, err
	}

	d.recents.Add(snap.Hash, snap) //@keep，clique的recent和snapshot的recents各有一个recents，clique的recent就是一个LRU， snapshot中的recent记录了最近几个块的签名者。

	// If we've generated a new checkpoint snapshot, save to disk
	//@keep, len(headers) 说明这个epoch的snapshot 原来没有，是重建出来的，则将Snapshot对象存储到数据库中
	if snap.Number%d.config.Epoch == 0 && len(headers) > 0 {
		if err = snap.store(d.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (d *Dawn) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (d *Dawn) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (d *Dawn) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, d.validator)
}

func (d *Dawn) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "dawn",
		Version:   "1.0",
		Service:   &API{chain: chain, dawn: d},
		Public:    true,
	}}
}

func calcDifficulty(snap *Snapshot, validator common.Address) *big.Int {
	if snap.inturn(snap.Number+1, validator) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// DawnRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func DawnRLP(header *types.Header, chainId *big.Int) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, chainId)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	enc := []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}
