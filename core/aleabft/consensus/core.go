package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
)

type Core struct {
	Name           core.NodeID
	Committee      core.Committee
	Parameters     core.Parameters
	SigService     *crypto.SigService
	Store          *store.Store
	TxPool         *pool.Pool
	Transimtor     *core.Transmitor
	Aggreator      *Aggreator                       //用于聚合签名 coin的生成
	Commitor       *Committor                       //用于提交提案block
	Epoch          int64                            //用于CBC
	LeaderEpoch    int64                            //用于ABA
	abaHeight      map[core.NodeID]int64            //存储每个ABA开始的位置，在ABA结束之前不能提前提交
	abaInstances   map[int64]map[int64]*ABA         //aba实例的二维数组 ID epoch
	boltInstances  map[int64]map[core.NodeID]*Bolt  //Bolt实例的二维数组 ID epoch
	prepareSet     map[int64][]*Prepare             //存储每个Epoch的Prepare消息
	commitments    map[core.NodeID]map[int64]*Block //N个优先队列存储n个经过Blot的可以准备提交（已经收到了commitment）的实例（这个实例具体用什么表示还没想好）
	uncommitBlocks []struct {
		leader core.NodeID
		height int64
	}
	BoltCallBack chan *BoltBack
	abaCallBack  chan *ABABack
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
		abaHeight:     make(map[core.NodeID]int64),
		abaInstances:  make(map[int64]map[int64]*ABA),
		boltInstances: make(map[int64]map[core.NodeID]*Bolt),
		prepareSet:    make(map[int64][]*Prepare),
		commitments:   make(map[core.NodeID]map[int64]*Block),
		uncommitBlocks: make([]struct {
			leader core.NodeID
			height int64
		}, 0),
		BoltCallBack: make(chan *BoltBack, 1000),
		abaCallBack:  make(chan *ABABack, 1000),
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
func (c *Core) abamessageFilter(epoch int64) bool {
	return c.LeaderEpoch > epoch
}

/**************************** Utils ********************************/
/**************************** Message Handle ********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Epoch)
	if p.Epoch == 0 { //如果是创世纪块，直接给fullsignature赋值为全零数组的默认值
		p.fullSignature = make([]byte, 32) // 创建一个长度为 32 的字节切片，默认值为 0
		if err := c.storeBlock(p.B); err != nil {
			return err
		}
		//加入到本地队列中
		if c.commitments[p.Author] == nil {
			c.commitments[p.Author] = make(map[int64]*Block)
			c.commitments[p.Author][p.Epoch] = p.B
		} else {
			c.commitments[p.Author][p.Epoch] = p.B
		}
	}
	go c.getBoltInstance(p.Epoch, p.Author).ProcessProposal(p)
	return nil
}

// 处理投票消息
func (c *Core) handleVote(r *Vote) error {
	logger.Debug.Printf("Processing Vote proposer %d epoch %d from %d\n", r.Proposer, r.Epoch, r.Author)
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
	//记录每个人在每条队列上的参与ABA的高度
	//快速路径提前提交，不用等到ABA结束提交 fastpath
	if lens > 2 {
		//检查是否还有没有提交完的块
		for i := 0; i < len(c.uncommitBlocks); i++ {
			logger.Debug.Printf("entering next aba but still have uncommitblocks")
			name := c.uncommitBlocks[i].leader
			height := c.uncommitBlocks[i].height
			if c.commitments[name][height] != nil {
				c.Commitor.Commit(height, name, c.commitments[name][height])
				//在map中删除这个元素
				c.uncommitBlocks = append(c.uncommitBlocks[:i], c.uncommitBlocks[i+1:]...)
				i--
				//logger.Error.Printf("aba final commit height %d node %d batchid %d\n",height,name, c.commitments[name][height].Batch.ID)
			} else {
				break
			}
		}
		for i := c.abaHeight[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))]; i < int64(lens-2); i++ {
			if c.commitments[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))][i] == nil {
				logger.Error.Printf("fast commit error commit height %d node %d\n", i, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())))
				//往uncommit集合中加入这个元素
				c.uncommitBlocks = append(c.uncommitBlocks, struct {
					leader core.NodeID
					height int64
				}{
					leader: core.NodeID(c.LeaderEpoch % int64(c.Committee.Size())),
					height: i,
				})
			} else {
				if len(c.uncommitBlocks) == 0 {
					c.Commitor.Commit(i, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), c.commitments[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))][i])
					//logger.Error.Printf("commit height %d node %d batchid %d\n",i,core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), c.commitments[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))][i].Batch.ID)
				} else {
					//加入uncommit集合中
					c.uncommitBlocks = append(c.uncommitBlocks, struct {
						leader core.NodeID
						height int64
					}{
						leader: core.NodeID(c.LeaderEpoch % int64(c.Committee.Size())),
						height: i,
					})
				}
			}
		}
		c.abaHeight[core.NodeID(c.LeaderEpoch%int64(c.Committee.Size()))] = int64(lens - 2)
	}
	prepare, _ := NewPrepare(c.Name, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), c.LeaderEpoch, max(int64(lens-1), 0), c.SigService) //传递的是高度为h-1的块，因为最高块可能只有自己收到了
	c.Transimtor.Send(c.Name, core.NONE, prepare)
	c.Transimtor.RecvChannel() <- prepare
	return nil
}

// 处理prepare阶段的消息  这里可以对队列中的内容进行填充
func (c *Core) handlePrepare(val *Prepare) error {
	logger.Debug.Printf("Processing  prepare leader %d proposer %d epoch %d \n", val.Author, val.Proposer, val.Epoch)

	if c.abamessageFilter(val.Epoch) {
		return nil
	}
	c.prepareSet[val.Epoch] = append(c.prepareSet[val.Epoch], val)
	var maxprepare *Prepare
	if len(c.prepareSet[val.Epoch]) == c.Committee.HightThreshold() {
		for _, v := range c.prepareSet[val.Epoch] {
			if maxprepare == nil || v.Height > maxprepare.Height {
				maxprepare = v
			}
		}
		//向ABA输入值创建newABAval
		abaVal, _ := NewABAVal(c.Name, core.NodeID(c.LeaderEpoch%int64(c.Committee.Size())), val.Epoch, 0, maxprepare.Height, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return nil

}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d val %d\n", val.Leader, val.Epoch, val.Round, val.Val)
	if c.abamessageFilter(val.Epoch) {
		return nil
	}

	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}
func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.Val)
	if c.abamessageFilter(mux.Epoch) {
		return nil
	}
	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)
	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share epoch %d round %d ", share.Epoch, share.Round)
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
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d\n", halt.Leader, halt.Epoch, halt.Round)
	if c.abamessageFilter(halt.Epoch) {
		return nil
	}
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt) //收到之后也广播halt消息

	return c.handleOutput(halt.Val, halt.Leader)
}

func (c *Core) handleAsk(ask *AskVal) error {
	if c.commitments[ask.Leader][ask.Height] != nil {
		//logger.Error.Printf("send value to  %d height %d node %d\n",ask.Author,ask.Height,ask.Leader)
		answerVal, _ := NewAnswerVal(c.Name, ask.Leader, ask.Height, c.commitments[ask.Leader][ask.Height], c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, answerVal)
		c.Transimtor.RecvChannel() <- answerVal
	}
	return nil
}

func (c *Core) handleAnswer(ans *AnswerVal) error {
	//logger.Error.Printf("recieve help  value from   %d height %d node %d\n",ans.Author,ans.Height,ans.Leader)
	if c.commitments[ans.Leader][ans.Height] != nil {
		return nil
	} else {
		c.commitments[ans.Leader][ans.Height] = ans.B
	}
	return nil
}

func (c *Core) handleOutput(epoch int64, leader core.NodeID) error { //ABA commit只需要决定是commit一个块还是两个块
	for i := 0; i < len(c.uncommitBlocks); i++ {
		logger.Debug.Printf("aba finished but still have uncommitblocks")
		name := c.uncommitBlocks[i].leader
		height := c.uncommitBlocks[i].height
		if c.commitments[name][height] != nil {
			c.Commitor.Commit(height, name, c.commitments[name][height])
			//在map中删除这个元素
			c.uncommitBlocks = append(c.uncommitBlocks[:i], c.uncommitBlocks[i+1:]...)
			i--
			//logger.Error.Printf("aba final commit height %d node %d batchid %d\n",height,leader, c.commitments[name][height].Batch.ID)
		} else {
			break
		}
	}
	for i := c.abaHeight[leader]; i <= epoch; i++ {
		//有可能c.commitments[leader][i]没有，那么就要向别人去要这个值
		if c.commitments[leader][i] != nil {
			if len(c.uncommitBlocks) == 0 {
				c.Commitor.Commit(i, leader, c.commitments[leader][i])
				//logger.Error.Printf("aba final commit height %d node %d batchid %d\n",i,leader, c.commitments[leader][i].Batch.ID)
			} else {
				//加入uncommit集合中
				c.uncommitBlocks = append(c.uncommitBlocks, struct {
					leader core.NodeID
					height int64
				}{
					leader: leader,
					height: i,
				})
			}

		} else {
			//这里还不一定能要到
			logger.Debug.Printf("ask val from %d epoch %d", leader, i)
			askVal, _ := NewAskVal(c.Name, leader, i, c.SigService)
			c.Transimtor.Send(c.Name, core.NONE, askVal)
			c.Transimtor.RecvChannel() <- askVal

			//把这个暂时不能提交的元素加入到数组中
			c.uncommitBlocks = append(c.uncommitBlocks, struct {
				leader core.NodeID
				height int64
			}{
				leader: leader,
				height: i,
			})
		}
	}
	c.abaHeight[leader] = int64(epoch + 1)
	c.abvanceNextABAEpoch(c.LeaderEpoch + 1)
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
	//恶意情况的实验
	if c.Name < core.NodeID(c.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", c.Name)
		return
	}

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
				case AskValType:
					err = c.handleAsk(msg.(*AskVal))
				case AnswerValType:
					err = c.handleAnswer(msg.(*AnswerVal))
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
