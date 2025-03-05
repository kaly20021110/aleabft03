package consensus

import (
	"bft/mvba/core"
	"bft/mvba/logger"
)

type Committor struct {
	Index        map[core.NodeID]int64 //对应的index
	commitBlocks map[int64]map[core.NodeID]*Block
	commitCh     chan *Block
	callBack     chan<- struct{}
}

func NewCommittor(callBack chan<- struct{}) *Committor {
	c := &Committor{
		Index:        make(map[core.NodeID]int64),
		commitBlocks: make(map[int64]map[core.NodeID]*Block),
		commitCh:     make(chan *Block, 100),
		callBack:     callBack,
	}
	go c.run()
	return c
}

func (c *Committor) run() {
	for block := range c.commitCh {
		if block.Batch.ID != -1 {
			logger.Info.Printf("commit Block epoch %d node %d batch_id %d \n", block.Height, block.Proposer, block.Batch.ID)
		}
		c.callBack <- struct{}{}
	}
}
