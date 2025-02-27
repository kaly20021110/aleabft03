package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bytes"
	"sync"
)

type BoltBack struct {
	Epoch      int64
	Author     core.NodeID
	Tag        uint8
	Commitment []bool
}

type Bolt struct {
	c              *Core
	Proposer       core.NodeID //相当于这个是提案的leader
	Epoch          int64
	BMutex         sync.Mutex
	BlockHash      *crypto.Digest
	fullSignature  []byte      //本轮的full签名 也就是本轮的commitment
	cachedVote     []*Vote     //收集的vote消息
	cachedProposal []*Proposal //存储Proposal
	voteShares     map[int64][]crypto.SignatureShare
	boltCallBack   chan *BoltBack
}

func NewBolt(c *Core, Proposer core.NodeID, Epoch int64, boltCallBack chan *BoltBack) *Bolt {
	bolt := &Bolt{
		c:              c,
		Proposer:       Proposer,
		Epoch:          Epoch,
		BMutex:         sync.Mutex{},
		BlockHash:      nil,
		cachedVote:     make([]*Vote, 0),
		cachedProposal: make([]*Proposal, 0),
		voteShares:     make(map[int64][]crypto.SignatureShare),
		boltCallBack:   boltCallBack,
	}
	return bolt
}

// 处理提案消息
func (instance *Bolt) ProcessProposal(p *Proposal) error {
	//already recieve
	if p.Author != instance.Proposer {
		return nil
	}
	instance.BMutex.Lock()
	d := p.B.Hash()
	instance.BlockHash = &d
	instance.c.storeBlock(p.B)
	instance.BMutex.Unlock()

	if p.Epoch >= 1 {
		if bytes.Equal(p.fullSignature, instance.c.getBoltInstance(p.Epoch-1, p.Author).fullSignature) {
			//logger.Info.Printf("begining to commit epoch %d node %d batch_id %d \n",p.Epoch-1, p.Author,instance.c.commitments[p.Author][p.Epoch-1].Batch.ID)
			if instance.c.commitments[p.Author] == nil {
				instance.c.commitments[p.Author] = make(map[int64]*Block)
			}
			instance.c.commitments[p.Author][p.Epoch] = p.B
			ready, _ := NewVote(instance.c.Name, instance.Proposer, p.Epoch, p.B, instance.c.SigService)
			if instance.c.Name == instance.Proposer {
				instance.c.Transimtor.RecvChannel() <- ready
			} else {
				instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
			}
		}
	}else{
			ready, _ := NewVote(instance.c.Name, instance.Proposer, p.Epoch, p.B, instance.c.SigService)
			if instance.c.Name == instance.Proposer {
				instance.c.Transimtor.RecvChannel() <- ready
			} else {
				instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
			}
	}
	return nil
}

func (instance *Bolt) ProcessVote(r *Vote) error {
	if r.Proposer != instance.Proposer {
		return nil
	}
	instance.voteShares[r.Epoch] = append(instance.voteShares[r.Epoch], r.Signature)
	cnts := len(instance.voteShares[r.Epoch])          //2f+1个vote消息
	//logger.Error.Printf("receiving vote epoch%d counting %d\n", r.Epoch, cnts)
	if cnts == instance.c.Committee.HightThreshold() { //生成2f+1的聚合签名
		//make real proposal
		data, err := crypto.CombineIntactTSPartial(instance.voteShares[r.Epoch], instance.c.SigService.ShareKey, r.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return nil
		}
		instance.fullSignature = data //把Bolt的全签名赋值为新生成的聚合签名
		instance.c.getBoltInstance(r.Epoch,r.Author).fullSignature = data
		instance.c.Epoch = instance.Epoch + 1
		logger.Error.Printf("entering next epoch and begining to generate blocks epoch%d \n", instance.c.Epoch)
		block := instance.c.generateBlock(instance.c.Epoch)
		// 提出新的提案
		proposal, _ := NewProposal(instance.c.Name, block, instance.Epoch+1, instance.c.SigService)
		proposal.fullSignature = instance.fullSignature
		instance.c.Transimtor.Send(instance.c.Name, core.NONE, proposal)
		instance.c.Transimtor.RecvChannel() <- proposal
	}
	return nil
}
