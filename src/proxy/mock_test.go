// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Fantom-foundation/go-lachesis/src/proxy (interfaces: App,Node,Consensus)

// Package proxy is a generated GoMock package.
package proxy

import (
	reflect "reflect"

	hash "github.com/Fantom-foundation/go-lachesis/src/hash"
	inter "github.com/Fantom-foundation/go-lachesis/src/inter"
	pos "github.com/Fantom-foundation/go-lachesis/src/inter/pos"
	common "github.com/ethereum/go-ethereum/common"
	gomock "github.com/golang/mock/gomock"
)

// MockApp is a mock of App interface
type MockApp struct {
	ctrl     *gomock.Controller
	recorder *MockAppMockRecorder
}

// MockAppMockRecorder is the mock recorder for MockApp
type MockAppMockRecorder struct {
	mock *MockApp
}

// NewMockApp creates a new mock instance
func NewMockApp(ctrl *gomock.Controller) *MockApp {
	mock := &MockApp{ctrl: ctrl}
	mock.recorder = &MockAppMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockApp) EXPECT() *MockAppMockRecorder {
	return m.recorder
}

// CommitHandler mocks base method
func (m *MockApp) CommitHandler(arg0 inter.Block) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CommitHandler", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CommitHandler indicates an expected call of CommitHandler
func (mr *MockAppMockRecorder) CommitHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CommitHandler", reflect.TypeOf((*MockApp)(nil).CommitHandler), arg0)
}

// RestoreHandler mocks base method
func (m *MockApp) RestoreHandler(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RestoreHandler", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RestoreHandler indicates an expected call of RestoreHandler
func (mr *MockAppMockRecorder) RestoreHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestoreHandler", reflect.TypeOf((*MockApp)(nil).RestoreHandler), arg0)
}

// SnapshotHandler mocks base method
func (m *MockApp) SnapshotHandler(arg0 int64) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SnapshotHandler", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SnapshotHandler indicates an expected call of SnapshotHandler
func (mr *MockAppMockRecorder) SnapshotHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SnapshotHandler", reflect.TypeOf((*MockApp)(nil).SnapshotHandler), arg0)
}

// MockNode is a mock of Node interface
type MockNode struct {
	ctrl     *gomock.Controller
	recorder *MockNodeMockRecorder
}

// MockNodeMockRecorder is the mock recorder for MockNode
type MockNodeMockRecorder struct {
	mock *MockNode
}

// NewMockNode creates a new mock instance
func NewMockNode(ctrl *gomock.Controller) *MockNode {
	mock := &MockNode{ctrl: ctrl}
	mock.recorder = &MockNodeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNode) EXPECT() *MockNodeMockRecorder {
	return m.recorder
}

// AddInternalTxn mocks base method
func (m *MockNode) AddInternalTxn(arg0 inter.InternalTransaction) (hash.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddInternalTxn", arg0)
	ret0, _ := ret[0].(hash.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddInternalTxn indicates an expected call of AddInternalTxn
func (mr *MockNodeMockRecorder) AddInternalTxn(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddInternalTxn", reflect.TypeOf((*MockNode)(nil).AddInternalTxn), arg0)
}

// GetID mocks base method
func (m *MockNode) GetID() common.Address {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(common.Address)
	return ret0
}

// GetID indicates an expected call of GetID
func (mr *MockNodeMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockNode)(nil).GetID))
}

// GetInternalTxn mocks base method
func (m *MockNode) GetInternalTxn(arg0 hash.Transaction) (*inter.InternalTransaction, *inter.Event) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInternalTxn", arg0)
	ret0, _ := ret[0].(*inter.InternalTransaction)
	ret1, _ := ret[1].(*inter.Event)
	return ret0, ret1
}

// GetInternalTxn indicates an expected call of GetInternalTxn
func (mr *MockNodeMockRecorder) GetInternalTxn(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInternalTxn", reflect.TypeOf((*MockNode)(nil).GetInternalTxn), arg0)
}

// MockConsensus is a mock of Consensus interface
type MockConsensus struct {
	ctrl     *gomock.Controller
	recorder *MockConsensusMockRecorder
}

// MockConsensusMockRecorder is the mock recorder for MockConsensus
type MockConsensusMockRecorder struct {
	mock *MockConsensus
}

// NewMockConsensus creates a new mock instance
func NewMockConsensus(ctrl *gomock.Controller) *MockConsensus {
	mock := &MockConsensus{ctrl: ctrl}
	mock.recorder = &MockConsensusMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockConsensus) EXPECT() *MockConsensusMockRecorder {
	return m.recorder
}

// GetEventBlock mocks base method
func (m *MockConsensus) GetEventBlock(arg0 hash.Event) *inter.Block {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEventBlock", arg0)
	ret0, _ := ret[0].(*inter.Block)
	return ret0
}

// GetEventBlock indicates an expected call of GetEventBlock
func (mr *MockConsensusMockRecorder) GetEventBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEventBlock", reflect.TypeOf((*MockConsensus)(nil).GetEventBlock), arg0)
}

// StakeOf mocks base method
func (m *MockConsensus) StakeOf(arg0 common.Address) pos.Stake {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StakeOf", arg0)
	ret0, _ := ret[0].(pos.Stake)
	return ret0
}

// StakeOf indicates an expected call of StakeOf
func (mr *MockConsensusMockRecorder) StakeOf(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StakeOf", reflect.TypeOf((*MockConsensus)(nil).StakeOf), arg0)
}
