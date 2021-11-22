package main

import (
	"fmt"
	"crypto/ecdsa"
	"math/rand"
	"time"
	"math/big"
	"bytes"
	"io"
	"compress/gzip"
	"errors"
	"crypto/sha256"
	"os"

	"github.com/millicentnetwork/go-opera/inter"
	"github.com/millicentnetwork/go-opera/inter/validatorpk"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/millicentnetwork/go-opera/opera"
	"github.com/millicentnetwork/go-opera/opera/genesis"
	"github.com/millicentnetwork/go-opera/opera/genesis/netinit"
	"github.com/millicentnetwork/go-opera/opera/genesis/driver"
	"github.com/millicentnetwork/go-opera/opera/genesis/driverauth"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/millicentnetwork/go-opera/opera/genesis/evmwriter"
	"github.com/millicentnetwork/go-opera/opera/genesis/sfc"
	"github.com/millicentnetwork/go-opera/opera/genesis/gpos"
	"github.com/millicentnetwork/go-opera/utils/iodb"
	"github.com/millicentnetwork/go-opera/utils/ioread"
	"github.com/status-im/keycard-go/hexutils"
	"github.com/millicentnetwork/lachesis-base/kvdb/memorydb"
	"github.com/millicentnetwork/lachesis-base/kvdb/table"

	"github.com/millicentnetwork/go-opera/logger"
	"github.com/millicentnetwork/go-opera/utils/rlpstore"
	"github.com/millicentnetwork/lachesis-base/common/bigendian"
	"github.com/millicentnetwork/lachesis-base/hash"
	"github.com/millicentnetwork/lachesis-base/inter/idx"
	"github.com/millicentnetwork/lachesis-base/kvdb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

type InputGenesis struct {
	Hash  hash.Hash
	Read  func(*Store) error
	Close func() error
}

var (
	FakeGenesisTime = inter.Timestamp(1608600000 * time.Second)
	fileHeader  = hexutils.HexToBytes("641b00ac")
	fileVersion = hexutils.HexToBytes("00010001")
)

// FakeKey gets n-th fake private key.
func FakeKey(n int) *ecdsa.PrivateKey {
	reader := rand.New(rand.NewSource(int64(n)))

	key, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic(err)
	}

	return key
}

func FakeGenesisStore(num int, balance, stake *big.Int) *Store {
	genStore := NewMemStore()
	genStore.SetRules(opera.FakeNetRules())

	validators := GetFakeValidators(num)

	totalSupply := new(big.Int)
	for _, val := range validators {
		genStore.SetEvmAccount(val.Address, genesis.Account{
			Code:    []byte{},
			Balance: balance,
			Nonce:   0,
		})
		genStore.SetDelegation(val.Address, val.ID, genesis.Delegation{
			Stake:              stake,
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})
		totalSupply.Add(totalSupply, balance)
	}

	var owner common.Address
	if num != 0 {
		owner = validators[0].Address
	}

	genStore.SetMetadata(Metadata{
		Validators:    validators,
		FirstEpoch:    2,
		Time:          FakeGenesisTime,
		PrevEpochTime: FakeGenesisTime - inter.Timestamp(time.Hour),
		ExtraData:     []byte("fake"),
		DriverOwner:   owner,
		TotalSupply:   totalSupply,
	})
	genStore.SetBlock(0, genesis.Block{
		Time:        FakeGenesisTime - inter.Timestamp(time.Minute),
		Atropos:     hash.Event{},
		Txs:         types.Transactions{},
		InternalTxs: types.Transactions{},
		Root:        hash.Hash{},
		Receipts:    []*types.ReceiptForStorage{},
	})
	// pre deploy NetworkInitializer
	genStore.SetEvmAccount(netinit.ContractAddress, genesis.Account{
		Code:    netinit.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriver
	genStore.SetEvmAccount(driver.ContractAddress, genesis.Account{
		Code:    driver.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriverAuth
	genStore.SetEvmAccount(driverauth.ContractAddress, genesis.Account{
		Code:    driverauth.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy SFC
	genStore.SetEvmAccount(sfc.ContractAddress, genesis.Account{
		Code:    sfc.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// set non-zero code for pre-compiled contracts
	genStore.SetEvmAccount(evmwriter.ContractAddress, genesis.Account{
		Code:    []byte{0},
		Balance: new(big.Int),
		Nonce:   0,
	})

	return genStore
}

func GetFakeValidators(num int) gpos.Validators {
	validators := make(gpos.Validators, 0, num)

	for i := 1; i <= num; i++ {
		key := FakeKey(i)
		addr := crypto.PubkeyToAddress(key.PublicKey)
		pubkeyraw := crypto.FromECDSAPub(&key.PublicKey)
		validatorID := idx.ValidatorID(i)
		validators = append(validators, gpos.Validator{
			ID:      validatorID,
			Address: addr,
			PubKey: validatorpk.PubKey{
				Raw:  pubkeyraw,
				Type: validatorpk.Types.Secp256k1,
			},
			CreationTime:     FakeGenesisTime,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		})
	}

	return validators
}

func (s *Store) Export(writer io.Writer) error {
	return iodb.Write(writer, s.db)
}

func (s *Store) Import(reader io.Reader) error {
	return iodb.Read(reader, s.db.NewBatch())
}

func checkFileHeader(reader io.Reader) error {
	headerAndVersion := make([]byte, len(fileHeader)+len(fileVersion))
	err := ioread.ReadAll(reader, headerAndVersion)
	if err != nil {
		return err
	}
	if bytes.Compare(headerAndVersion[:len(fileHeader)], fileHeader) != 0 {
		return errors.New("expected a genesis file, mismatched file header")
	}
	if bytes.Compare(headerAndVersion[len(fileHeader):], fileVersion) != 0 {
		got := hexutils.BytesToHex(headerAndVersion[len(fileHeader):])
		expected := hexutils.BytesToHex(fileVersion)
		return errors.New(fmt.Sprintf("wrong version of genesis file, got=%s, expected=%s", got, expected))
	}
	return nil
}

func OpenGenesisStore(rawReader io.Reader) (h hash.Hash, readGenesisStore func(*Store) error, err error) {
	err = checkFileHeader(rawReader)
	if err != nil {
		return hash.Zero, nil, err
	}
	err = ioread.ReadAll(rawReader, h[:])
	if err != nil {
		return hash.Zero, nil, err
	}
	readGenesisStore = func(genesisStore *Store) error {
		gzipReader, err := gzip.NewReader(rawReader)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		err = genesisStore.Import(gzipReader)
		if err != nil {
			return err
		}
		return nil
	}
	return h, readGenesisStore, nil
}

func WriteGenesisStore(rawWriter io.Writer, genesisStore *Store) error {
	_, err := rawWriter.Write(append(fileHeader, fileVersion...))
	if err != nil {
		return err
	}
	h := genesisStore.Hash()
	_, err = rawWriter.Write(h[:])
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(rawWriter)
	defer gzipWriter.Close()
	err = genesisStore.Export(gzipWriter)
	if err != nil {
		return err
	}
	return nil
}

// Store is a node persistent storage working over physical key-value database.
type Store struct {
	db kvdb.Store

	table struct {
		Rules kvdb.Store `table:"c"`

		Blocks kvdb.Store `table:"b"`

		EvmAccounts kvdb.Store `table:"a"`
		EvmStorage  kvdb.Store `table:"s"`
		RawEvmItems kvdb.Store `table:"M"`

		Delegations kvdb.Store `table:"d"`
		Metadata    kvdb.Store `table:"m"`
	}

	rlp rlpstore.Helper
	logger.Instance
}

// NewMemStore creates store over memory map.
func NewMemStore() *Store {
	return NewStore(memorydb.New())
}

// NewStore creates store over key-value db.
func NewStore(db kvdb.Store) *Store {
	s := &Store{
		db:       db,
		Instance: logger.MakeInstance(),
		rlp:      rlpstore.Helper{logger.MakeInstance()},
	}

	table.MigrateTables(&s.table, s.db)

	return s
}

// Close leaves underlying database.
func (s *Store) Close() {
	table.MigrateTables(&s.table, nil)

	_ = s.db.Close()
}

type (
	Metadata struct {
		Validators    gpos.Validators
		FirstEpoch    idx.Epoch
		Time          inter.Timestamp
		PrevEpochTime inter.Timestamp
		ExtraData     []byte
		DriverOwner   common.Address
		TotalSupply   *big.Int
	}
	Accounts struct {
		Raw kvdb.Iteratee
	}
	Storage struct {
		Raw kvdb.Iteratee
	}
	Delegations struct {
		Raw kvdb.Iteratee
	}
	Blocks struct {
		Raw kvdb.Iteratee
	}
)

func (s *Store) EvmAccounts() genesis.Accounts {
	return &Accounts{s.table.EvmAccounts}
}

func (s *Store) SetEvmAccount(addr common.Address, acc genesis.Account) {
	s.rlp.Set(s.table.EvmAccounts, addr.Bytes(), &acc)
}

func (s *Store) GetEvmAccount(addr common.Address) genesis.Account {
	w, ok := s.rlp.Get(s.table.EvmAccounts, addr.Bytes(), &genesis.Account{}).(*genesis.Account)
	if !ok {
		return genesis.Account{
			Code:    []byte{},
			Balance: new(big.Int),
			Nonce:   0,
		}
	}
	return *w
}

func (s *Store) EvmStorage() genesis.Storage {
	return &Storage{s.table.EvmStorage}
}

func (s *Store) SetEvmState(addr common.Address, key common.Hash, value common.Hash) {
	err := s.table.EvmStorage.Put(append(addr.Bytes(), key.Bytes()...), value.Bytes())
	if err != nil {
		s.Log.Crit("Failed to put key-value", "err", err)
	}
}

func (s *Store) GetEvmState(addr common.Address, key common.Hash) common.Hash {
	valBytes, err := s.table.EvmStorage.Get(append(addr.Bytes(), key.Bytes()...))
	if err != nil {
		s.Log.Crit("Failed to get key-value", "err", err)
	}
	if len(valBytes) == 0 {
		return common.Hash{}
	}
	return common.BytesToHash(valBytes)
}

func (s *Store) Delegations() genesis.Delegations {
	return &Delegations{s.table.Delegations}
}

func (s *Store) SetDelegation(addr common.Address, toValidatorID idx.ValidatorID, delegation genesis.Delegation) {
	s.rlp.Set(s.table.Delegations, append(addr.Bytes(), toValidatorID.Bytes()...), &delegation)
}

func (s *Store) GetDelegation(addr common.Address, toValidatorID idx.ValidatorID) genesis.Delegation {
	w, ok := s.rlp.Get(s.table.Delegations, append(addr.Bytes(), toValidatorID.Bytes()...), &genesis.Delegation{}).(*genesis.Delegation)
	if !ok {
		return genesis.Delegation{
			Stake:              new(big.Int),
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		}
	}
	return *w
}

func (s *Store) Blocks() genesis.Blocks {
	return &Blocks{s.table.Blocks}
}

func (s *Store) SetBlock(index idx.Block, block genesis.Block) {
	s.rlp.Set(s.table.Blocks, index.Bytes(), &block)
}

func (s *Store) SetRawEvmItem(key, value []byte) {
	err := s.table.RawEvmItems.Put(key, value)
	if err != nil {
		s.Log.Crit("Failed to put key-value", "err", err)
	}
}

func (s *Store) GetMetadata() Metadata {
	metadata := s.rlp.Get(s.table.Metadata, []byte("m"), &Metadata{}).(*Metadata)
	return *metadata
}

func (s *Store) SetMetadata(metadata Metadata) {
	s.rlp.Set(s.table.Metadata, []byte("m"), &metadata)
}

func (s *Store) GetRules() opera.Rules {
	cfg := s.rlp.Get(s.table.Rules, []byte("c"), &opera.Rules{}).(*opera.Rules)
	return *cfg
}

func (s *Store) SetRules(cfg opera.Rules) {
	s.rlp.Set(s.table.Rules, []byte("c"), &cfg)
}

func (s *Store) GetGenesis() opera.Genesis {
	meatadata := s.GetMetadata()
	return opera.Genesis{
		Accounts:      s.EvmAccounts(),
		Storage:       s.EvmStorage(),
		Delegations:   s.Delegations(),
		Blocks:        s.Blocks(),
		RawEvmItems:   s.table.RawEvmItems,
		Validators:    meatadata.Validators,
		FirstEpoch:    meatadata.FirstEpoch,
		PrevEpochTime: meatadata.PrevEpochTime,
		Time:          meatadata.Time,
		ExtraData:     meatadata.ExtraData,
		TotalSupply:   meatadata.TotalSupply,
		DriverOwner:   meatadata.DriverOwner,
		Rules:         s.GetRules(),
		Hash:          s.Hash,
	}
}

func (s *Accounts) ForEach(fn func(common.Address, genesis.Account)) {
	it := s.Raw.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		addr := common.BytesToAddress(it.Key())
		acc := genesis.Account{}
		err := rlp.DecodeBytes(it.Value(), &acc)
		if err != nil {
			log.Crit("Genesis accounts error", "err", err)
		}
		fn(addr, acc)
	}
}

func (s *Storage) ForEach(fn func(common.Address, common.Hash, common.Hash)) {
	it := s.Raw.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		addr := common.BytesToAddress(it.Key()[:20])
		key := common.BytesToHash(it.Key()[20:])
		val := common.BytesToHash(it.Value())
		fn(addr, key, val)
	}
}

func (s *Delegations) ForEach(fn func(common.Address, idx.ValidatorID, genesis.Delegation)) {
	it := s.Raw.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		addr := common.BytesToAddress(it.Key()[:20])
		to := idx.BytesToValidatorID(it.Key()[20:])
		delegation := genesis.Delegation{}
		err := rlp.DecodeBytes(it.Value(), &delegation)
		if err != nil {
			log.Crit("Genesis delegations error", "err", err)
		}
		fn(addr, to, delegation)
	}
}

func (s *Blocks) ForEach(fn func(idx.Block, genesis.Block)) {
	it := s.Raw.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		index := idx.BytesToBlock(it.Key())
		block := genesis.Block{}
		err := rlp.DecodeBytes(it.Value(), &block)
		if err != nil {
			log.Crit("Genesis blocks error", "err", err)
		}
		fn(index, block)
	}
}

func (s *Store) Hash() hash.Hash {
	hasher := sha256.New()
	it := s.db.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		k := it.Key()
		v := it.Value()
		hasher.Write(bigendian.Uint32ToBytes(uint32(len(k))))
		hasher.Write(k)
		hasher.Write(bigendian.Uint32ToBytes(uint32(len(v))))
		hasher.Write(v)
	}
	return hash.BytesToHash(hasher.Sum(nil))
}

func main() {
	fmt.Println("Hello World!")
	const count = 3
	genesisStore := FakeGenesisStore(count, big.NewInt(999998), big.NewInt(10000))

	f, _ := os.OpenFile("/tmp/genesis.g", os.O_WRONLY|os.O_CREATE, 0600)
	WriteGenesisStore(f, genesisStore);
}