package dawn

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

type chainContext struct {
	chain consensus.ChainHeaderReader
	dawn  consensus.Engine
}

func newChainContext(chain consensus.ChainHeaderReader, engine consensus.Engine) *chainContext {
	return &chainContext{
		chain: chain,
		dawn:  engine,
	}
}

func (c chainContext) Engine() consensus.Engine {
	return c.dawn
}

func (c chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.chain.GetHeader(hash, number)
}
