package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
)

type Core struct {
	Name          core.NodeID
	Committee     core.Committee
	Parameters    core.Parameters
	SigService    *crypto.SigService
	Store         *store.Store
	TxPool        *pool.Pool
	Transimtor    *core.Transmitor
	Commitor      *Committor
	Aggreator     *Aggreator
	Height        int64 //the height of block, height++, then create block, the height of the first block is 1
	ABAEpoch      int64
	cbcCallBack   chan *CBCBack
	cbcInstances  map[int64]map[core.NodeID]*CBC          //epoch-node-tag
	commitments   map[core.NodeID]map[int64]bool          //check if recieve commitment
	cbcHeight     map[core.NodeID]int64                   //存储每个节点共识的高度
	queue         map[core.NodeID]map[int64]crypto.Digest //存储收到的block
	abaInstances  map[int64]map[int64]*ABA
	abaInvokeFlag map[int64]map[int64]map[int64]map[uint8]struct{} //aba invoke flag
	abaCallBack   chan *ABABack
}

func NewCore(
	name core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	CallBack chan<- struct{},
) *Core {
	core := &Core{
		Name:          name,
		Committee:     committee,
		Parameters:    parameters,
		SigService:    SigService,
		Store:         Store,
		TxPool:        TxPool,
		Transimtor:    Transimtor,
		Commitor:      NewCommittor(CallBack),
		Aggreator:     NewAggreator(committee, SigService),
		Height:        0,
		ABAEpoch:      0,
		cbcCallBack:   make(chan *CBCBack, 1000),
		cbcInstances:  make(map[int64]map[core.NodeID]*CBC),
		commitments:   make(map[core.NodeID]map[int64]bool),
		cbcHeight:     make(map[core.NodeID]int64),
		queue:         make(map[core.NodeID]map[int64]crypto.Digest),
		abaInstances:  make(map[int64]map[int64]*ABA),
		abaInvokeFlag: make(map[int64]map[int64]map[int64]map[uint8]struct{}),
		abaCallBack:   make(chan *ABABack, 1000),
	}

	return core
}

func (c *Core) storeBlock(block *Block) error {
	key := block.Hash()
	val, err := block.Encode()
	if err != nil {
		return err
	}
	if err := c.Store.Write(key[:], val); err != nil {
		return err
	}
	return nil
}

func (c *Core) getBlock(digest crypto.Digest) (*Block, error) {
	data, err := c.Store.Read(digest[:])
	if err != nil {
		return nil, err
	}
	block := &Block{}
	err = block.Decode(data)
	return block, err
}

func (c *Core) getCBCInstance(epoch int64, node core.NodeID) *CBC {
	items, ok := c.cbcInstances[epoch]
	if !ok {
		items = make(map[core.NodeID]*CBC)
		c.cbcInstances[epoch] = items
	}
	item, ok := items[node]
	if !ok {
		item = NewCBC(c, node, epoch, c.cbcCallBack)
		items[node] = item
	}
	return item
}

func (c *Core) getABAInstance(epoch, round int64) *ABA {
	items, ok := c.abaInstances[epoch]
	if !ok {
		items = make(map[int64]*ABA)
		c.abaInstances[epoch] = items
	}
	instance, ok := items[round]
	if !ok {
		instance = NewABA(c, epoch, round, c.abaCallBack)
		items[round] = instance
	}
	return instance
}

func (c *Core) abamessageFilter(epoch int64) bool {
	return c.ABAEpoch > epoch
}

func (c *Core) cbcmessageFilter(Height int64) bool {
	return c.Height > Height
}

func (c *Core) generateBlock(epoch int64) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), epoch)
	if block.Batch.ID != -1 {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Height, block.Proposer, block.Batch.ID)
	}
	return block
}

/**************************** Protocol ********************************/
func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Height)
	if err := c.storeBlock(p.B); err != nil {
		return err
	}
	if c.queue[p.Author] == nil {
		c.queue[p.Author] = make(map[int64]crypto.Digest)
	}
	c.queue[p.Author][p.Height] = p.B.Hash()

	go c.getCBCInstance(p.Height, p.Author).ProcessProposal(p)

	return nil
}

func (c *Core) handleVote(r *Vote) error {
	logger.Debug.Printf("Processing vote proposer %d leader %d Height %d\n", r.Author, r.Proposer, r.Height)
	if c.cbcmessageFilter(r.Height) {
		return nil
	}
	go c.getCBCInstance(r.Height, r.Proposer).ProcessVote(r)
	return nil
}

func (c *Core) handleCommitment(val *Commitment) error {
	logger.Debug.Printf("Processing Commitment  author %d Height %d\n", val.Author, val.Height)
	if c.commitments[val.Author] == nil {
		c.commitments[val.Author] = make(map[int64]bool)
	}
	c.commitments[val.Author][val.Height] = true
	return nil
}

func (c *Core) startABA(leaderepoch int64) error {
	flags, ok := c.abaInvokeFlag[leaderepoch]
	if !ok {
		flags = make(map[int64]map[int64]map[uint8]struct{})
		c.abaInvokeFlag[leaderepoch] = flags
	}
	items, ok := flags[0]
	if !ok {
		items = make(map[int64]map[uint8]struct{})
		flags[0] = items
	}
	item, ok := items[0]
	if !ok {
		item = make(map[uint8]struct{})
		items[0] = item
	}
	leader := core.NodeID(leaderepoch % int64(c.Committee.Size()))
	priority := c.cbcHeight[leader]
	if c.commitments[leader][priority] {
		item[1] = struct{}{}
		abaVal, _ := NewABAVal(c.Name, leader, leaderepoch, 0, 0, uint8(1), c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	} else {
		item[0] = struct{}{}
		abaVal, _ := NewABAVal(c.Name, leader, leaderepoch, 0, 0, uint8(0), c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return nil
}

func (c *Core) isInvokeABA(epoch, round, inRound int64, tag uint8) bool {
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		return false
	}
	flag, ok := flags[round]
	if !ok {
		return false
	}
	item, ok := flag[inRound]
	if !ok {
		return false
	}
	_, ok = item[tag]
	return ok
}

func (c *Core) invokeABAVal(leader core.NodeID, epoch, round, inRound int64, flag uint8) error {
	logger.Debug.Printf("Invoke ABA epoch %d ex_round %d in_round %d val %d\n", epoch, round, inRound, flag)
	if c.isInvokeABA(epoch, round, inRound, flag) {
		return nil
	}
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		flags = make(map[int64]map[int64]map[uint8]struct{})
		c.abaInvokeFlag[epoch] = flags
	}
	items, ok := flags[round]
	if !ok {
		items = make(map[int64]map[uint8]struct{})
		flags[round] = items
	}
	item, ok := items[inRound]
	if !ok {
		item = make(map[uint8]struct{})
		items[inRound] = item
	}
	item[flag] = struct{}{}
	abaVal, _ := NewABAVal(c.Name, leader, epoch, round, inRound, flag, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, abaVal)
	c.Transimtor.RecvChannel() <- abaVal

	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d in-round %d val %d\n", val.Leader, val.Epoch, val.Round, val.InRound, int64(val.Flag))
	if c.abamessageFilter(val.Epoch) {
		return nil
	}
	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)
	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d in-round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.InRound, mux.Flag)
	if c.abamessageFilter(mux.Epoch) {
		return nil
	}
	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share epoch %d round %d in-round %d", share.Epoch, share.Round, share.InRound)
	if c.abamessageFilter(share.Epoch) {
		return nil
	}

	if ok, coin, err := c.Aggreator.addCoinShare(share); err != nil {
		return err
	} else if ok {
		logger.Debug.Printf("ABA epoch %d ex-round %d in-round %d coin %d\n", share.Epoch, share.Round, share.InRound, coin)
		go c.getABAInstance(share.Epoch, share.Round).ProcessCoin(share.InRound, coin, share.Leader)
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d val %d\n", halt.Leader, halt.Epoch, halt.Round, halt.Flag)
	if c.abamessageFilter(halt.Epoch) {
		return nil
	}
	height := c.cbcHeight[halt.Leader]
	if halt.Flag == 1 {
		c.cbcHeight[halt.Leader] = c.cbcHeight[halt.Leader] + 1
	}
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt) //收到之后也广播halt消息

	return c.handleOutput(halt.Flag, halt.Leader, height)
}

func (c *Core) processABABack(back *ABABack) error {
	if back.Typ == ABA_INVOKE {
		return c.invokeABAVal(back.Leader, back.Epoch, back.ExRound, back.InRound, back.Flag)
	} else if back.Typ == ABA_HALT {
		c.handleOutput(back.Flag, back.Leader, back.Height)
	}
	return nil
}

func (c *Core) handleOutput(val uint8, leader core.NodeID, height int64) error {
	if val == 1 {
		blockhash := c.queue[leader][height]
		if block, err := c.getBlock(blockhash); err != nil {
			logger.Info.Printf("No block when commit height %d author %d\n", height, leader)
			return err
		} else {
			c.Commitor.commitCh <- block
		}
	}
	return c.abvanceNextABAEpoch()

}

func (c *Core) abvanceNextABAEpoch() error {
	c.ABAEpoch++
	logger.Debug.Printf("abvanceNextABAEpoch leader %d \n", c.ABAEpoch)
	id := core.NodeID(c.ABAEpoch % int64(c.Committee.Size()))
	height := c.cbcHeight[id]
	if c.commitments[id][height] {
		logger.Debug.Printf("c.commitments[id][height] id %d height %d is true", id, height)
		abaVal, _ := NewABAVal(c.Name, id, c.ABAEpoch, 0, 0, uint8(1), c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	} else {
		logger.Debug.Printf("c.commitments[id][height] id %d height %d is false", id, height)
		abaVal, _ := NewABAVal(c.Name, id, c.ABAEpoch, 0, 0, uint8(0), c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return nil
}

func (c *Core) Run() {
	c.Height++
	block := c.generateBlock(c.Height)
	proposal, err := NewProposal(c.Name, block, c.Height, c.SigService)
	if err != nil {
		panic(err)
	}
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal

	recvChan := c.Transimtor.RecvChannel()

	go c.startABA(c.ABAEpoch)

	for {
		var err error
		select {
		case msg := <-recvChan:
			{
				if v, ok := msg.(Validator); ok {
					if !v.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
					}
				}

				switch msg.MsgType() {
				case ProposalType:
					err = c.handleProposal(msg.(*Proposal))
				case VoteType:
					err = c.handleVote(msg.(*Vote))
				case CommitmentType:
					err = c.handleCommitment(msg.(*Commitment))
				case ABAValType:
					err = c.handleABAVal(msg.(*ABAVal))
				case ABAMuxType:
					err = c.handleABAMux(msg.(*ABAMux))
				case CoinShareType:
					err = c.handleCoinShare(msg.(*CoinShare))
				case ABAHaltType:
					err = c.handleABAHalt(msg.(*ABAHalt))
				}

			}
		case abaBack := <-c.abaCallBack:
			err = c.processABABack(abaBack)
		}

		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
