package opera

import (
	"math/big"

	"github.com/millicentnetwork/lachesis-base/hash"
	"github.com/millicentnetwork/lachesis-base/inter/idx"
	"github.com/ethereum/go-ethereum/common"

	"github.com/millicentnetwork/go-opera/inter"
	"github.com/millicentnetwork/go-opera/opera/genesis"
	"github.com/millicentnetwork/go-opera/opera/genesis/gpos"
)

type Genesis struct {
	Accounts    genesis.Accounts
	Storage     genesis.Storage
	Delegations genesis.Delegations
	Blocks      genesis.Blocks
	RawEvmItems genesis.RawEvmItems
	Validators  gpos.Validators

	FirstEpoch    idx.Epoch
	PrevEpochTime inter.Timestamp
	Time          inter.Timestamp
	ExtraData     []byte

	TotalSupply *big.Int

	DriverOwner common.Address

	Rules Rules

	Hash func() hash.Hash
}
