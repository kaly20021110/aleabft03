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
func (instance *Bolt) ProcessProposal(p *Proposal) {
	if p.Author != instance.Proposer {
		return
	}
	instance.BMutex.Lock()
	d := p.B.Hash()
	instance.BlockHash = &d
	instance.BMutex.Unlock()

	if p.Epoch >= 1 {
		if bytes.Equal(p.fullSignature, instance.c.boltInstances[p.Epoch-1][p.Author].fullSignature) {
			//将上一个块加入到队列中，准备提交
			instance.c.commitments[p.Author][p.Epoch] = p.B
			instance.c.Commitor.Commit(p.Epoch-1, p.Author, instance.c.commitments[p.Author][p.Epoch-1])
			instance.c.storeBlock(instance.c.commitments[p.Author][p.Epoch-1])
		}
	}
	//创建投票并且将投票发送给leader
	ready, _ := NewVote(instance.c.Name, instance.Proposer, instance.Epoch, p.B, instance.c.SigService)
	if instance.c.Name == instance.Proposer {
		instance.c.Transimtor.RecvChannel() <- ready
	} else {
		instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
	}
	return
}

func (instance *Bolt) ProcessVote(r *Vote) {
	if r.Author != instance.Proposer {
		return
	}
	instance.voteShares[r.Epoch] = append(instance.voteShares[r.Epoch], r.Signature)
	cnts := len(instance.voteShares[r.Epoch])          //2f+1个vote消息
	if cnts == instance.c.Committee.HightThreshold() { //生成2f+1的聚合签名
		//make real proposal
		data, err := crypto.CombineIntactTSPartial(instance.voteShares[r.Epoch], instance.c.SigService.ShareKey, r.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return
		}
		instance.fullSignature = data //把Bolt的全签名赋值为新生成的聚合签名
		instance.c.boltInstances[r.Epoch][r.Author].fullSignature = data
		instance.c.Epoch = instance.Epoch + 1
		block := instance.c.generateBlock(instance.c.Epoch)
		// 提出新的提案
		proposal, _ := NewProposal(instance.c.Name, block, instance.Epoch+1, instance.c.SigService)

		proposal.fullSignature = instance.fullSignature

		//这一步好像写错了
		if instance.c.Name == instance.Proposer {
			instance.c.Transimtor.RecvChannel() <- proposal
		} else {
			instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, proposal)
		}
	}
	return
}
