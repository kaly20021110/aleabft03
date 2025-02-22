package consensus

import (
	"bft/mvba/core"
	"bft/mvba/logger"
)

type Committor struct {
	Index        int64
	commitBlocks map[int64]map[core.NodeID]*Block
	commitCh     chan *Block
	callBack     chan<- struct{}
}

func NewCommittor(callBack chan<- struct{}) *Committor {
	c := &Committor{
		Index:        0,
		commitBlocks: make(map[int64]map[core.NodeID]*Block),
		commitCh:     make(chan *Block, 100),
		callBack:     callBack,
	}
	go c.run()
	return c
}

func (c *Committor) Commit(epoch int64, leader core.NodeID, block *Block) {
	if epoch < c.Index {
		return
	}
	if block == nil {
		return
	}
	c.commitBlocks[epoch][leader] = block
	for {
		if block, ok := c.commitBlocks[c.Index][leader]; ok {
			c.commitCh <- block
			delete(c.commitBlocks, c.Index)
			c.Index++
		} else {
			break
		}
	}
}

func (c *Committor) run() {
	for block := range c.commitCh {
		if block.Batch.Txs != nil {
			logger.Info.Printf("commit Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
		}
		c.callBack <- struct{}{}
	}
}
