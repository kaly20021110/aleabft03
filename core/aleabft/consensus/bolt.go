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
	vm               sync.Mutex
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
		vm:               sync.Mutex{},
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
	if bytes.Equal(p.proof, instance.c.commitments[p.Author][p.Height-1]) {
		if vote, err := NewVote(instance.c.Name, p.Author, p.Height, blockHash, instance.c.SigService); err != nil {
			logger.Error.Printf("create spb vote message error:%v \n", err)
		} else {
			logger.Debug.Printf("create vote message author %d height %d", p.Author, p.Height)
			if instance.c.Name == instance.Proposer {
				instance.c.Transimtor.RecvChannel() <- vote
			} else {
				instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, vote)
			}
		}
	} else {
		logger.Debug.Printf("do not receive the commitment of the previs block")
		instance.uvm.Lock()
		instance.unHandleProposal = append(instance.unHandleProposal, p)
		instance.uvm.Unlock()
		return nil
	}

	// if bytes.Equal(p.proof, instance.c.commitments[p.Author][p.Height-1]) {
	// }

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
	if instance.c.Name != r.Proposer {
		return nil
	}
	instance.vm.Lock()
	num, proof, _ := instance.c.Aggreator.AddVote(r)
	instance.vm.Unlock()
	if num == BV_HIGH_FLAG {
		//make real proposal
		instance.c.Height++
		block := instance.c.generatorBlock(instance.c.Height, r.BlockHash)
		if proposal, err := NewProposal(instance.c.Name, block, instance.c.Height, proof, instance.c.SigService); err != nil {
			logger.Error.Printf("create proposal message error:%v \n", err)
		} else {
			instance.c.commitments[proposal.Author][proposal.Height-1] = proposal.proof //创建新块的时候带上这个块
			logger.Debug.Printf("create proposal message author %d height %d", proposal.Author, proposal.Height)
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
