package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
)

type Aggreator struct {
	committee  core.Committee
	sigService *crypto.SigService
	votes      map[int64]*VoteAggreator           //epoch  投票聚合成签名，用于bolt部分
	coins      map[int64]map[int64]*CoinAggreator //epoch-round 用于硬币的生成
}

func NewAggreator(committee core.Committee, sigService *crypto.SigService) *Aggreator {
	a := &Aggreator{
		committee:  committee,
		sigService: sigService,
		votes:      make(map[int64]*VoteAggreator),
		coins:      make(map[int64]map[int64]*CoinAggreator),
	}
	return a
}

// func (a *Aggreator) addVote(vote *Vote) (bool, []byte, error) {
// 	items, ok := a.votes[vote.Epoch] //检查这个轮次是否已经生成了vote聚合器
// 	if !ok {
// 		items = NewVoteAggreator()
// 		a.votes[vote.Epoch] = items
// 	}
// 	return items.append(a.committee, a.sigService, vote)
// }

func (a *Aggreator) addCoinShare(coinShare *CoinShare) (bool, int64, error) {
	items, ok := a.coins[coinShare.Epoch]
	if !ok {
		items = make(map[int64]*CoinAggreator)
		a.coins[coinShare.Epoch] = items
	}
	item, ok := items[coinShare.Round]
	if !ok {
		item = NewCoinAggreator()
		items[coinShare.Round] = item
	}
	return item.append(a.committee, a.sigService, coinShare)
}

type VoteAggreator struct { //专门用于收集部分签名然后聚合
	Used   map[core.NodeID]struct{}
	Shares []crypto.SignatureShare
}

func NewVoteAggreator() *VoteAggreator {
	return &VoteAggreator{
		Used:   make(map[core.NodeID]struct{}),
		Shares: make([]crypto.SignatureShare, 0),
	}
}

// func (v *VoteAggreator) append(committee core.Committee, sigService *crypto.SigService, vote *Vote) (bool, []byte, error) {
// 	if _, ok := v.Used[vote.Author]; ok {
// 		return false, []byte{}, core.ErrOneMoreMessage(vote.MsgType(), vote.Epoch, 0, vote.Author)
// 	}
// 	v.Shares = append(v.Shares, vote.Signature)      //把部分签名加入到部分签名集合中
// 	if len(v.Shares) == committee.HightThreshold() { //得到完整的fullsignature 她的本质是byte[]
// 		data, err := crypto.CombineIntactTSPartial(v.Shares, sigService.ShareKey, vote.Hash())
// 		if err != nil {
// 			logger.Error.Printf("Combine signature error: %v\n", err)
// 			return false, []byte{}, err
// 		}
// 		return true, data, nil
// 	}
// 	return false, []byte{}, nil
// }

type CoinAggreator struct {
	Used   map[core.NodeID]struct{}
	Shares []crypto.SignatureShare
}

func NewCoinAggreator() *CoinAggreator {
	return &CoinAggreator{
		Used:   make(map[core.NodeID]struct{}),
		Shares: make([]crypto.SignatureShare, 0),
	}
}

func (c *CoinAggreator) append(committee core.Committee, sigService *crypto.SigService, share *CoinShare) (bool, int64, error) {
	if _, ok := c.Used[share.Author]; ok {
		return false, 0, core.ErrOneMoreMessage(share.MsgType(), share.Epoch, share.Round, share.Author)
	}
	c.Shares = append(c.Shares, share.Share)
	if len(c.Shares) == committee.HightThreshold() {
		var seed uint64 = 0
		data, err := crypto.CombineIntactTSPartial(c.Shares, sigService.ShareKey, share.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return false, 0, err
		}
		for i := 0; i < len(data) && i < 7; i++ { //RANDOM_LEN = 7
			seed = seed<<8 + uint64(data[i])
		}
		return true, int64(seed % 2), nil
	}

	return false, 0, nil
}
