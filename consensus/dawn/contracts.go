package dawn

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/dawn/systemcontracts"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"math"
	"math/big"
)

func (d *Dawn) getCurrentValidators(blockHash common.Hash, blockNumber *big.Int) ([]common.Address, error) {
	// block
	blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)

	// method
	method := "getValidators"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	data, err := d.validatorsABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, err
	}
	// call
	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(systemcontracts.Validators)
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	result, err := d.ethAPI.Call(ctx, ethapi.TransactionArgs{
		Gas:  &gas,
		To:   &toAddress,
		Data: &msgData,
	}, blockNr, nil)
	if err != nil {
		return nil, err
	}

	var (
		ret0 = new([]common.Address)
	)
	out := ret0

	if err := d.validatorsABI.UnpackIntoInterface(out, method, result); err != nil {
		return nil, err
	}

	valz := make([]common.Address, len(*ret0))
	for i, a := range *ret0 {
		valz[i] = a
	}
	return valz, nil
}

// TODO(keep), 获取系统税率
func (d *Dawn) getSystemTaxRatio(blockHash common.Hash) (uint64, uint64, error) {
	return 1, 100, nil
	//// block
	//blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)
	//
	//// method
	//method := "getTaxRatio"
	//
	//ctx, cancel := context.WithCancel(context.Background())
	//defer cancel() // cancel when we are finished consuming integers
	//
	//data, err := d.vaultABI.Pack(method)
	//if err != nil {
	//	log.Error("Unable to pack tx for get TaxRatio", "error", err)
	//	return 0, 100, err
	//}
	//
	//// call
	//msgData := (hexutil.Bytes)(data)
	//toAddress := common.HexToAddress(systemcontracts.Vault)
	//gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	//result, err := d.ethAPI.Call(ctx, ethapi.TransactionArgs{
	//	Gas:  &gas,
	//	To:   &toAddress,
	//	Data: &msgData,
	//}, blockNr, nil)
	//if err != nil {
	//	return 0, 100, err
	//}
	//
	//var (
	//	ret0 = new(big.Int)
	//)
	//out := ret0
	//
	//if err := d.validatorsABI.UnpackIntoInterface(out, method, result); err != nil {
	//	return 0, 100, err
	//}
	//
	////TODO(keep),返回ratio 和base， 比如1, 100 表示税率为1%
	//return 0, 100, nil
}

// TODO(keep), 获取系统税率
func (d *Dawn) getCommissionRatio(blockHash common.Hash, validator common.Address) (uint64, uint64, error) {
	return 0, 100, nil
	//// block
	//blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)
	//
	//// method
	//method := "getTaxRatio"
	//
	//ctx, cancel := context.WithCancel(context.Background())
	//defer cancel() // cancel when we are finished consuming integers
	//
	//data, err := d.vaultABI.Pack(method)
	//if err != nil {
	//	log.Error("Unable to pack tx for get TaxRatio", "error", err)
	//	return 0, 100, err
	//}
	//
	//// call
	//msgData := (hexutil.Bytes)(data)
	//toAddress := common.HexToAddress(systemcontracts.Vault)
	//gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	//result, err := d.ethAPI.Call(ctx, ethapi.TransactionArgs{
	//	Gas:  &gas,
	//	To:   &toAddress,
	//	Data: &msgData,
	//}, blockNr, nil)
	//if err != nil {
	//	return 0, 100, err
	//}
	//
	//var (
	//	ret0 = new(big.Int)
	//)
	//out := ret0
	//
	//if err := d.validatorsABI.UnpackIntoInterface(out, method, result); err != nil {
	//	return 0, 100, err
	//}
	//
	////TODO(keep),返回ratio 和base， 比如1, 100 表示税率为1%
	//return 0, 100, nil
}

// init contract
func (d *Dawn) initContract(chain consensus.ChainHeaderReader, state *state.StateDB, header *types.Header, chainContext core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	snap, err := d.snapshot(chain, 0, header.ParentHash, nil)
	if err != nil {
		return err
	}

	genesisValidators := snap.validators()
	if len(genesisValidators) == 0 || len(genesisValidators) > maxValidators {
		return errInvalidValidatorsNumber
	}

	method := "initialize"
	contracts := []struct {
		addr    common.Address
		packFun func() ([]byte, error)
	}{
		{common.HexToAddress(systemcontracts.Validators), func() ([]byte, error) {
			return d.validatorsABI.Pack(method, genesisValidators)
		}},
		{common.HexToAddress(systemcontracts.Slasher), func() ([]byte, error) {
			return d.slasherABI.Pack(method)
		}},
		{common.HexToAddress(systemcontracts.Commissions), func() ([]byte, error) {
			return d.commissionsABI.Pack(method)
		}},
	}

	for _, contract := range contracts {
		data, err := contract.packFun()
		if err != nil {
			return err
		}

		msg := d.newSystemMessage(header.Coinbase, contract.addr, data, common.Big0)
		// apply message
		log.Trace("init contract", "block hash", header.Hash(), "contract", contract)
		err = d.applyTransaction(msg, state, header, chainContext, txs, receipts, receivedTxs, usedGas, mining)
		if err != nil {
			return err
		}

	}
	return nil
}

// slash spoiled validators
func (d *Dawn) slash(validator common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "slash"

	// get packed data
	data, err := d.slasherABI.Pack(method,
		validator,
	)
	if err != nil {
		log.Error("Unable to pack tx for slash", "error", err)
		return err
	}
	// get system message
	msg := d.newSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.Slasher), data, common.Big0)
	// apply message
	return d.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// slash spoiled validators
func (d *Dawn) distributeBlockReward(validator common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	//coinbase := header.Coinbase
	balance := state.GetBalance(consensus.FeeCollector)
	if balance.Cmp(common.Big0) <= 0 {
		return nil
	}
	state.SetBalance(consensus.FeeCollector, big.NewInt(0))
	//state.AddBalance(coinbase, balance)

	ratio, base, err := d.getSystemTaxRatio(header.ParentHash)

	tax := big.NewInt(0).Mul(balance, big.NewInt(int64(ratio)))
	tax = big.NewInt(0).Div(tax, big.NewInt(int64(base)))
	err = d.distributeToSystem(tax, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
	if err != nil {
		return err
	}
	log.Trace("distribute to system reward pool", "block hash", header.Hash(), "amount", tax)
	balance = balance.Sub(balance, tax)

	//@keep, 给validator 存钱。
	log.Trace("distribute to validator contract", "block hash", header.Hash(), "amount", balance)
	return d.distributeToValidator(balance, validator, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

func (d *Dawn) distributeToSystem(amount *big.Int, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// get system message
	msg := d.newSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.Vault), nil, amount)
	// apply message
	return d.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

func (d *Dawn) distributeToValidator(amount *big.Int, validator common.Address,
	state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	state.AddBalance(validator, amount)
	return nil
	//TODO(keep)
	//// method
	//method := "distribute"
	//
	//// get packed data
	//data, err := d.validatorsABI.Pack(method,
	//	validator,
	//)
	//if err != nil {
	//	log.Error("Unable to pack tx for deposit", "error", err)
	//	return err
	//}
	//// get system message
	//msg := d.newSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.Validators), data, amount)
	//// apply message
	//return d.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// callmsg implements core.Message to allow passing it as a transaction simulator.
type callmsg struct {
	ethereum.CallMsg
}

func (m callmsg) From() common.Address { return m.CallMsg.From }
func (m callmsg) Nonce() uint64        { return 0 }
func (m callmsg) CheckNonce() bool     { return false }
func (m callmsg) To() *common.Address  { return m.CallMsg.To }
func (m callmsg) GasPrice() *big.Int   { return m.CallMsg.GasPrice }
func (m callmsg) Gas() uint64          { return m.CallMsg.Gas }
func (m callmsg) Value() *big.Int      { return m.CallMsg.Value }
func (m callmsg) Data() []byte         { return m.CallMsg.Data }

// get system message
// @keep, 组装系统消息，注意gasPrice = 0
func (d *Dawn) newSystemMessage(from, toAddress common.Address, data []byte, value *big.Int) callmsg {
	return callmsg{
		ethereum.CallMsg{
			From:     from,
			Gas:      math.MaxUint64 / 2,
			GasPrice: big.NewInt(0),
			Value:    value,
			To:       &toAddress,
			Data:     data,
		},
	}
}

func (d *Dawn) applyTransaction(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainContext core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt,
	receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool,
) (err error) {
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), msg.Gas(), msg.GasPrice(), msg.Data())
	expectedHash := d.signer.Hash(expectedTx)

	if msg.From() == d.validator && mining {
		expectedTx, err = d.signTxFn(accounts.Account{Address: msg.From()}, expectedTx, d.chainConfig.ChainID)
		if err != nil {
			return err
		}
	} else {
		if receivedTxs == nil || len(*receivedTxs) == 0 || (*receivedTxs)[0] == nil {
			return errors.New("supposed to get a actual transaction, but get none")
		}
		actualTx := (*receivedTxs)[0]
		if !bytes.Equal(d.signer.Hash(actualTx).Bytes(), expectedHash.Bytes()) {
			return fmt.Errorf("expected tx hash %v, get %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s", expectedHash.String(), actualTx.Hash().String(),
				expectedTx.Nonce(),
				expectedTx.To().String(),
				expectedTx.Value().String(),
				expectedTx.Gas(),
				expectedTx.GasPrice().String(),
				hex.EncodeToString(expectedTx.Data()),
			)
		}
		expectedTx = actualTx
		// move to next
		*receivedTxs = (*receivedTxs)[1:]
	}
	state.Prepare(expectedTx.Hash(), len(*txs))
	gasUsed, err := applyMessage(msg, state, header, d.chainConfig, chainContext)
	if err != nil {
		return err
	}
	*txs = append(*txs, expectedTx)
	var root []byte
	if d.chainConfig.IsByzantium(header.Number) {
		state.Finalise(true)
	} else {
		root = state.IntermediateRoot(d.chainConfig.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gasUsed
	receipt := types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = expectedTx.Hash()
	receipt.GasUsed = gasUsed

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = state.GetLogs(expectedTx.Hash(), header.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(state.TxIndex())
	*receipts = append(*receipts, receipt)
	state.SetNonce(msg.From(), nonce+1)
	return nil
}

// apply message
func applyMessage(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainConfig *params.ChainConfig,
	chainContext core.ChainContext,
) (uint64, error) {
	// Create a new context to be used in the EVM environment
	context := core.NewEVMBlockContext(header, chainContext, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, vm.TxContext{Origin: msg.From(), GasPrice: big.NewInt(0)}, state, chainConfig, vm.Config{})
	// Apply the transaction to the current state (included in the env)
	ret, returnGas, err := vmenv.Call(
		vm.AccountRef(msg.From()),
		*msg.To(),
		msg.Data(),
		msg.Gas(),
		msg.Value(),
	)
	if err != nil {
		log.Error("apply message failed", "msg", string(ret), "err", err)
	}
	return msg.Gas() - returnGas, err
}
