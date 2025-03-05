package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"sync"
)

type CBCBack struct {
	Epoch      int64
	Author     core.NodeID
	Tag        uint8
	Commitment []bool
}

const (
	DATA_CBC   uint8 = 0
	COMMIT_CBC uint8 = 1
)

type CBC struct {
	c                *Core
	Proposer         core.NodeID
	Epoch            int64
	BMutex           sync.Mutex
	BlockHash        *crypto.Digest
	Commitment       []bool
	unHandleMutex    sync.Mutex
	unHandleProposal []*Proposal
	unHandleVote     []*Vote
	cbcCallBack      chan *CBCBack
}

func NewCBC(c *Core, Proposer core.NodeID, Epoch int64, cbcCallBack chan *CBCBack) *CBC {
	cbc := &CBC{
		c:                c,
		Proposer:         Proposer,
		Epoch:            Epoch,
		BMutex:           sync.Mutex{},
		BlockHash:        nil,
		Commitment:       nil,
		unHandleMutex:    sync.Mutex{},
		unHandleProposal: nil,
		unHandleVote:     nil,
		cbcCallBack:      cbcCallBack,
	}

	return cbc
}

func (instance *CBC) ProcessProposal(p *Proposal) {
	if p.Author != instance.Proposer {
		return
	}
	instance.BMutex.Lock()
	d := p.B.Hash()
	instance.BlockHash = &d
	instance.BMutex.Unlock()

	//make vote
	ready, _ := NewVote(instance.c.Name, instance.Proposer, instance.Epoch, p.B.Hash(), instance.c.SigService)

	if instance.c.Name == instance.Proposer {
		instance.c.Transimtor.RecvChannel() <- ready
	} else {
		instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
	}
}

func (instance *CBC) ProcessVote(r *Vote) error {
	if r.Proposer != instance.Proposer {
		return nil
	}
	//形成聚合签名作为证明
	num, proof, _ := instance.c.Aggreator.AddVote(r)
	if num == BV_HIGH_FLAG {
		//make real proposal
		instance.c.Height++
		block := instance.c.generateBlock(instance.c.Height)
		if proposal, err := NewProposal(instance.c.Name, block, instance.c.Height, instance.c.SigService); err != nil {
			logger.Error.Printf("create proposal message error:%v \n", err)
		} else {
			if instance.c.commitments[proposal.Author] == nil {
				instance.c.commitments[proposal.Author] = make(map[int64]bool)
			}
			instance.c.commitments[proposal.Author][proposal.Height-1] = true //创建新块的时候带上这个块
			logger.Debug.Printf("create proposal message author %d height %d\n", proposal.Author, proposal.Height)
			instance.c.Transimtor.Send(instance.c.Name, core.NONE, proposal)
			instance.c.Transimtor.RecvChannel() <- proposal

			if qc, err := NewCommitment(instance.Proposer, proof, r.Height, instance.c.SigService); err != nil {
				logger.Error.Printf("create commitment message error:%v \n", err)
			} else {
				logger.Debug.Printf("create commitment message author %d height %d\n", qc.Author, qc.Height)
				instance.c.Transimtor.Send(instance.c.Name, core.NONE, qc)
				instance.c.Transimtor.RecvChannel() <- qc
			}
		}
	}
	return nil
}
