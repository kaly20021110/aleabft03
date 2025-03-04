package consensus

import (
	"bft/mvba/core"
	"bft/mvba/logger"
	"bytes"
	"sync"
	"sync/atomic"
)

type Bolt struct {
	c                *Core
	Proposer         core.NodeID
	Epoch            int64
	BlockHash        atomic.Value
	uvm              sync.Mutex
	unHandleVote     []*Vote     //收集的vote消息
	unHandleProposal []*Proposal //存储Proposal
	LockFlag         atomic.Bool
}

func NewBolt(c *Core, Proposer core.NodeID, Epoch int64) *Bolt {
	bolt := &Bolt{
		c:                c,
		Proposer:         Proposer,
		Epoch:            Epoch,
		uvm:              sync.Mutex{},
		unHandleVote:     make([]*Vote, 0),
		unHandleProposal: make([]*Proposal, 0),
	}
	return bolt
}

func (instance *Bolt) ProcessProposal(p *Proposal) error {
	//already recieve
	if instance.BlockHash.Load() != nil || instance.Proposer != p.B.Proposer {
		return nil
	}
	blockHash := p.B.Hash()
	instance.BlockHash.Store(blockHash)
	if vote, err := NewVote(instance.c.Name, p.Author, p.Height, blockHash, instance.c.SigService); err != nil {
		logger.Error.Printf("create spb vote message error:%v \n", err)
	} else {
		if instance.c.Name == instance.Proposer {
			instance.c.Transimtor.RecvChannel() <- vote
		} else {
			instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, vote)
		}
	}

	if bytes.Equal(p.proof, instance.c.commitments[p.Author][p.Height-1]) {
	}

	instance.uvm.Lock()
	for _, proposal := range instance.unHandleProposal {
		go instance.ProcessProposal(proposal)
	}
	for _, vote := range instance.unHandleVote {
		go instance.ProcessVote(vote)
	}
	instance.unHandleProposal = nil
	instance.unHandleVote = nil
	instance.uvm.Unlock()
	return nil
}

func (instance *Bolt) ProcessVote(r *Vote) error {
	if instance.BlockHash.Load() == nil {
		instance.uvm.Lock()
		instance.unHandleVote = append(instance.unHandleVote, r)
		instance.uvm.Unlock()
		return nil
	}
	num, proof, _ := instance.c.Aggreator.AddVote(r)
	if num == BV_HIGH_FLAG {
		//make real proposal
		block := instance.c.generatorBlock(instance.c.Height, r.BlockHash)
		if proposal, err := NewProposal(instance.c.Name, block, instance.c.Height, proof, instance.c.SigService); err != nil {
			logger.Error.Printf("create proposal message error:%v \n", err)
		} else {
			instance.c.Transimtor.Send(instance.c.Name, core.NONE, proposal)
			instance.c.Transimtor.RecvChannel() <- proposal
		}
	}
	return nil
}

func (s *Bolt) IsLock() bool {
	return s.LockFlag.Load()
}

func (s *Bolt) GetBlockHash() any {
	return s.BlockHash.Load()
}
