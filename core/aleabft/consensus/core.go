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
	Aggreator     *Aggreator //用于聚合签名 coin的生成以及vote的聚合
	Commitor      *Committor //用于提交提案block
	Epoch         int64
	LeaderEpoch   int64
	abaInstances  map[int64]map[int64]*ABA         //aba实例的二维数组 ID epoch
	boltInstances map[int64]map[core.NodeID]*Bolt  //Bolt实例的二维数组 ID epoch
	prepareSet    map[int64][]*Prepare             //存储每个Epoch的Prepare消息,没太懂这个prepare消息具体在做什么
	commitments   map[core.NodeID]map[int64]*Block //N个优先队列存储n个经过Blot的可以准备提交（已经收到了commitment）的实例（这个实例具体用什么表示还没想好）
	BoltCallBack  chan *BoltBack
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
	callBack chan<- struct{},
) *Core {
	core := &Core{
		Name:          name,
		Committee:     committee,
		Parameters:    parameters,
		SigService:    SigService,
		Store:         Store,
		TxPool:        TxPool,
		Transimtor:    Transimtor,
		Aggreator:     NewAggreator(committee, SigService),
		Commitor:      NewCommittor(callBack),
		Epoch:         0,
		LeaderEpoch:   0,
		abaInstances:  make(map[int64]map[int64]*ABA),
		boltInstances: make(map[int64]map[core.NodeID]*Bolt),
		prepareSet:    make(map[int64][]*Prepare),
		commitments:   make(map[core.NodeID]map[int64]*Block),
		BoltCallBack:  make(chan *BoltBack, 1000),
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

func (c *Core) getBlock(digest crypto.Digest) (*Block, error) { //通过哈希值找block
	data, err := c.Store.Read(digest[:])
	if err != nil {
		return nil, err
	}
	block := &Block{}
	err = block.Decode(data)
	return block, err
}

func (c *Core) getBoltInstance(epoch int64, node core.NodeID) *Bolt {
	items, ok := c.boltInstances[epoch]
	if !ok {
		items = make(map[core.NodeID]*Bolt)
		c.boltInstances[epoch] = items
	}
	item, ok := items[node]
	if !ok {
		item = NewBolt(c, node, epoch, c.BoltCallBack)
		items[node] = item
	}
	return item
}

func (c *Core) getABAInstance(epoch, round int64) *ABA { //ABA是轮流来的，所以只需要一个即可,但是ABA不一定执行几轮，所以需要round参数
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

func (c *Core) generateBlock(epoch int64) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), epoch)
	if block.Batch.Txs != nil {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
	}
	return block
}

/**************************** Utils ********************************/
func (c *Core) messageFilter(epoch int64) bool {
	return c.Epoch > epoch
}

/**************************** Utils ********************************/
/**************************** Message Handle ********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Epoch)
	if c.messageFilter(p.Epoch) { //相当于收到的提案已经过期了
		return nil
	}
	if p.Epoch == 0 { //如果是创世纪块，直接给fullsignature赋值为全零数组的默认值
		p.fullSignature = make([]byte, 32) // 创建一个长度为 32 的字节切片，默认值为 0
		//如果是创世纪块可以直接加入队列 把block先存进队列中
		if err := c.storeBlock(p.B); err != nil {
			return err
		}
		//加入到本地队列中
		if c.commitments[p.Author] == nil {
			c.commitments[p.Author] = make(map[int64]*Block)
			c.commitments[p.Author][p.Epoch] = p.B
		}
		//c.Commitor.Commit(p.Epoch, p.Author, p.B) //加入到提交池中
	}
	go c.getBoltInstance(p.Epoch, p.Author).ProcessProposal(p)
	return nil
}

// 处理投票消息
func (c *Core) handleVote(r *Vote) error {
	logger.Debug.Printf("Processing Vote proposer %d epoch %d\n", r.Proposer, r.Epoch)
	if c.messageFilter(r.Epoch) {
		return nil
	}
	go c.getBoltInstance(r.Epoch, r.Proposer).ProcessVote(r)
	return nil
}

func (c *Core) invokeABA() error {
	lens := 0
	if blockMap, exists := c.commitments[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))]; exists {
		lens = len(blockMap)
	}

	prepare, _ := NewPrepare(c.Name, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), c.LeaderEpoch, int64(lens), c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, prepare)
	c.Transimtor.RecvChannel() <- prepare
	return nil
}

// 处理prepare阶段的消息  这里可以对队列中的内容进行填充
func (c *Core) handlePrepare(val *Prepare) error {
	logger.Debug.Printf("Processing  prepare leader %d proposer %d epoch %d \n", val.Author, val.Proposer, val.Epoch)

	if c.messageFilter(val.Epoch) {
		return nil
	}
	c.prepareSet[val.Epoch] = append(c.prepareSet[val.Epoch], val)
	var maxprepare *Prepare
	if len(c.prepareSet[val.Epoch]) == c.Committee.HightThreshold() {
		for _, v := range c.prepareSet[val.Epoch] {
			if maxprepare == nil || v.Epoch > maxprepare.Epoch {
				maxprepare = v
			}
		}
		//向ABA输入值创建newABAval
		abaVal, _ := NewABAVal(c.Name, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), val.Epoch, 0, maxprepare.Epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return nil

}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d val %d\n", val.Leader, val.Epoch, val.Round, val.Val)
	if c.messageFilter(val.Epoch) {
		return nil
	}

	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.Val)
	if c.messageFilter(mux.Epoch) {
		return nil
	}

	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share epoch %d round %d ", share.Epoch, share.Round)
	if c.messageFilter(share.Epoch) {
		return nil
	}

	if ok, coin, err := c.Aggreator.addCoinShare(share); err != nil {
		return err
	} else if ok {
		logger.Debug.Printf("ABA epoch %d ex-round %d coin %d\n", share.Epoch, share.Round, coin)
		go c.getABAInstance(share.Epoch, share.Round).ProcessCoin(share.Round, coin, share.Leader)
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d\n", halt.Leader, halt.Epoch, halt.Round)
	if c.messageFilter(halt.Epoch) {
		return nil
	}
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt) //收到之后也广播halt消息

	c.abvanceNextABAEpoch(halt.Epoch + 1)

	return c.handleOutput(halt.Epoch, halt.Leader)
}

func (c *Core) handleOutput(epoch int64, leader core.NodeID) error { //直接提交或者间接提交
	cbc := c.getBoltInstance(epoch, leader)
	if cbc.BlockHash != nil {
		if block, err := c.getBlock(*cbc.BlockHash); err != nil {
			logger.Warn.Println(err)
			c.Commitor.Commit(epoch, leader, nil)
		} else {
			c.Commitor.Commit(epoch, leader, block)
			if block.Proposer != c.Name {
				temp := c.getBoltInstance(epoch, c.Name).BlockHash
				if temp != nil {
					if block, err := c.getBlock(*temp); err == nil && block != nil {
						c.TxPool.PutBatch(block.Batch)
					}
				}
			}
		}
	}
	return nil
}

/**************************** Message Handle ********************************/

/**************************** acctual run ********************************/
func (c *Core) abvanceNextABAEpoch(epoch int64) error {
	if epoch <= c.Epoch {
		return nil
	}
	logger.Debug.Printf("advance next abaepoch %d\n", epoch)
	c.LeaderEpoch = epoch
	c.invokeABA()
	return nil
}

func (c *Core) Run() {

	//创世纪块的创建 c.Epoch为0
	block := c.generateBlock(c.Epoch)
	proposal, err := NewProposal(c.Name, block, c.Epoch, c.SigService)
	if err != nil {
		panic(err)
	}
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal

	//开始执行产生Prepare消息
	c.invokeABA()

	recvChan := c.Transimtor.RecvChannel()
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
				case PrepareType:
					err = c.handlePrepare(msg.(*Prepare))
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
			// case boltBack := <-c.BoltCallBack:
			// 	err = c.processBoltBack(boltBack)
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}

/**************************** acctual run ********************************/
