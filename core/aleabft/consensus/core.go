package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
	"sync"
)

type Core struct {
	Name          core.NodeID
	Committee     core.Committee
	Parameters    core.Parameters
	SigService    *crypto.SigService
	Store         *store.Store
	TxPool        *pool.Pool
	Transimtor    *core.Transmitor
	Aggreator     *Aggreator                              //用于聚合签名 coin的生成
	Commitor      *Committor                              //用于提交提案block
	Height        int64                                   //the height of block, height++, then create block, the height of the first block is 1
	ABAEpoch      int64                                   //用于ABA
	BlockHashMap  map[core.NodeID]map[int64]crypto.Digest //map from NodeID to height to blockHash
	CurrentHeight map[core.NodeID]int64                   //CBC收集到的最高高度
	abaHeight     map[core.NodeID]int64                   //ABA得出来的结果
	abaInstances  map[int64]map[int64]*ABA                //aba实例的二维数组 ID epoch
	boltInstances map[int64]map[core.NodeID]*Bolt         //Bolt实例的二维数组 ID epoch
	prepareSet    map[int64][]*Prepare                    //存储每个Epoch的Prepare消息
	commitments   map[core.NodeID]map[int64][]byte        //N个优先队列存储n个经过Blot的可以准备提交（已经收到了commitment）的实例（这个实例具体用什么表示还没想好）
	abaCallBack   chan *ABABack
	blocklock     sync.Mutex
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
		Height:        0,
		ABAEpoch:      0,
		BlockHashMap:  make(map[core.NodeID]map[int64]crypto.Digest),
		CurrentHeight: make(map[core.NodeID]int64),
		abaHeight:     make(map[core.NodeID]int64),
		abaInstances:  make(map[int64]map[int64]*ABA),
		boltInstances: make(map[int64]map[core.NodeID]*Bolt),
		prepareSet:    make(map[int64][]*Prepare),
		commitments:   make(map[core.NodeID]map[int64][]byte),
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
		item = NewBolt(c, node, epoch)
		items[node] = item
	}
	return item
}

func (c *Core) getABAInstance(abaepoch, round int64) *ABA {
	items, ok := c.abaInstances[abaepoch]
	if !ok {
		items = make(map[int64]*ABA)
		c.abaInstances[abaepoch] = items
	}
	instance, ok := items[round]
	if !ok {
		instance = NewABA(c, abaepoch, round, c.abaCallBack)
		items[round] = instance
	}
	return instance
}

func (c *Core) generatorBlock(height int64, preHash crypto.Digest) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), height, preHash)
	if block.Batch.ID != -1 {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Height, block.Proposer, block.Batch.ID)
	}
	return block
}

func (c *Core) PbBroadcastBlock(preHash crypto.Digest) error {
	c.Height++
	logger.Debug.Printf("Broadcast Block node %d height %d\n", c.Name, c.Height)
	block := c.generatorBlock(c.Height, preHash)
	if proposal, err := NewProposal(c.Name, block, c.Height, nil, c.SigService); err != nil {
		logger.Error.Printf("create spb proposal message error:%v \n", err)
	} else {
		if c.commitments[c.Name] == nil {
			c.commitments[c.Name] = make(map[int64][]byte)
		}
		c.commitments[c.Name][c.Height-1] = nil
		c.Transimtor.Send(c.Name, core.NONE, proposal)
		c.Transimtor.RecvChannel() <- proposal
	}
	return nil
}

func (c *Core) StartABA() error {
	logger.Debug.Printf("StartABA and create prepare msg proposer %d  leader %d height %d\n", c.Name, core.NodeID(c.ABAEpoch%int64(c.Committee.Size())), 0)
	prepare, _ := NewPrepare(c.Name, core.NodeID(c.ABAEpoch%int64(c.Committee.Size())), c.ABAEpoch, 0, nil, nil, c.SigService) //传递的是高度为h-1的块，因为最高块可能只有自己收到了
	c.Transimtor.Send(c.Name, core.NONE, prepare)
	c.Transimtor.RecvChannel() <- prepare
	return nil
}

/**************************** Utils ********************************/

func (c *Core) abamessageFilter(epoch int64) bool {
	return c.ABAEpoch > epoch
}

/**************************** Utils ********************************/
/**************************** Message Handle ********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Height)
	if p.Height < c.CurrentHeight[p.Author] {
		return nil
	}
	c.CurrentHeight[p.Author] = p.Height - 1 //拥有的最高QC的高度

	if _, ok := c.BlockHashMap[p.Author]; !ok {
		c.BlockHashMap[p.Author] = make(map[int64]crypto.Digest)
	}
	c.BlockHashMap[p.Author][p.Height] = p.B.Hash()

	if err := c.storeBlock(p.B); err != nil {
		logger.Error.Printf("Store Block error: %v\n", err)
		return err
	}
	if _, oks := c.commitments[p.Author]; !oks {
		c.commitments[p.Author] = make(map[int64][]byte)
	}
	c.commitments[p.Author][p.Height-1] = p.proof
	go c.getBoltInstance(p.Height, p.Author).ProcessProposal(p)
	return nil
}

// 处理投票消息
func (c *Core) handleVote(r *Vote) error {
	logger.Debug.Printf("Processing Vote proposer %d epoch %d from %d\n", r.Proposer, r.Height, r.Author)
	go c.getBoltInstance(r.Height, r.Proposer).ProcessVote(r)
	return nil
}

// 处理prepare阶段的消息  这里可以对队列中的内容进行填充
func (c *Core) handlePrepare(val *Prepare) error {
	logger.Debug.Printf("Processing  prepare leader %d proposer %d epoch %d height %d\n", val.Author, val.Proposer, val.ABAEpoch, val.Height)

	if c.abamessageFilter(val.ABAEpoch) {
		return nil
	}
	//从prepare里面获取blocks
	if val.Block != nil {
		block, _ := c.getBlock(val.Block.Hash())
		if block == nil {
			c.storeBlock(val.Block)
			c.commitments[val.Author][val.Height] = val.proof
		}
	}
	c.prepareSet[val.ABAEpoch] = append(c.prepareSet[val.ABAEpoch], val)
	var maxprepare *Prepare
	if len(c.prepareSet[val.ABAEpoch]) == c.Committee.HightThreshold() {
		for _, v := range c.prepareSet[val.ABAEpoch] {
			if maxprepare == nil || v.Height > maxprepare.Height {
				maxprepare = v
			}
		}
		//向ABA输入值创建newABAval
		abaVal, _ := NewABAVal(c.Name, core.NodeID(c.ABAEpoch%int64(c.Committee.Size())), val.ABAEpoch, 0, maxprepare.Height, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val Author %d leader %d epoch %d round %d val %d\n", val.Author, val.Leader, val.Epoch, val.Round, val.Val)
	if c.abamessageFilter(val.Epoch) {
		return nil
	}
	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}
func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux Author %d leader %d epoch %d round %d val %d\n", mux.Author, mux.Leader, mux.Epoch, mux.Round, mux.Val)
	if c.abamessageFilter(mux.Epoch) {
		return nil
	}
	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)
	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share Author %d epoch %d round %d ", share.Author, share.Epoch, share.Round)
	if c.abamessageFilter(share.Epoch) {
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
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d height %d\n", halt.Leader, halt.Epoch, halt.Round, halt.Val)
	if c.abamessageFilter(halt.Epoch) {
		return nil
	}
	c.abaHeight[halt.Leader] = halt.Val
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt) //收到之后也广播halt消息

	return c.handleOutput(halt.Val, halt.Leader)
}

func (c *Core) handleOutput(height int64, leader core.NodeID) error {

	for i := c.abaHeight[leader]; i < height; i++ {
		c.blocklock.Lock()
		blockhash, ok := c.BlockHashMap[leader][i]
		c.blocklock.Unlock()
		if !ok {
			logger.Info.Printf("No block when commit height %d author %d\n", i, leader)
			continue
		}
		if block, err := c.getBlock(blockhash); err != nil {
			return err
		} else {
			c.Commitor.commitCh <- block
		}
	}
	c.abaHeight[leader] = height

	return c.abvanceNextABAEpoch()

}

/**************************** Message Handle ********************************/

/**************************** acctual run ********************************/
func (c *Core) abvanceNextABAEpoch() error {
	c.ABAEpoch++
	id := core.NodeID(c.ABAEpoch % int64(c.Committee.Size()))
	height := c.CurrentHeight[id]
	//logger.Info.Printf("abvanceNextABAEpoch c.CurrentHeight[id] %d  abaEpoc_id %d\n", c.CurrentHeight[id], id)
	//快速提交路径
	for i := c.abaHeight[id] + 1; i < height; i++ {

		c.blocklock.Lock()
		blockhash, ok := c.BlockHashMap[id][i]
		c.blocklock.Unlock()
		if !ok {
			logger.Info.Printf("No block when commit height %d author %d\n", i, id)
			continue
		}
		if block, err := c.getBlock(blockhash); err != nil {
			logger.Info.Printf("getBlock error %d author %d\n", i, id)
			return err
		} else {
			//logger.Info.Printf("abvanceNextABAEpoch fast path commit height %d node %d batch_id %d\n", i, id, block.Batch.ID)
			c.Commitor.commitCh <- block
		}
	}
	c.abaHeight[id] = height - 1
	qc := c.commitments[id][height]
	blockhash := c.BlockHashMap[id][height]
	block, _ := c.getBlock(blockhash)
	logger.Debug.Printf("advance next abaepoch %d\n", c.ABAEpoch)
	logger.Debug.Printf("StartABA and create prepare msg proposer %d  leader %d height %d\n", c.Name, id, height)
	prepare, _ := NewPrepare(c.Name, id, c.ABAEpoch, height, block, qc, c.SigService) //传递的是高度为h-1的块，因为最高块可能只有自己收到了
	c.Transimtor.Send(c.Name, core.NONE, prepare)
	c.Transimtor.RecvChannel() <- prepare
	return nil
}

func (c *Core) Run() {
	if c.Name < core.NodeID(c.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", c.Name)
		return
	}

	go c.PbBroadcastBlock(crypto.Digest{})
	go c.StartABA()

	//go c.TrytoStartABA() //这个地方不执行，等有PB完成了再开始ABA也不迟

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
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}

/**************************** acctual run ********************************/
