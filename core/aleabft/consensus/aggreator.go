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

func (a *Aggreator) AddVote(vote *Vote) (int8, []byte, error) {
	item, ok := a.votes[vote.Height]
	if !ok {
		item = NewVoteAggreator()
		a.votes[vote.Height] = item
	}
	return item.Append(a.committee, vote, a.sigService)
}

type VoteAggreator struct { //专门用于收集部分签名然后聚合
	Authors map[core.NodeID]struct{}
	Shares  []crypto.SignatureShare
}

func NewVoteAggreator() *VoteAggreator {
	return &VoteAggreator{
		Authors: make(map[core.NodeID]struct{}),
		Shares:  make([]crypto.SignatureShare, 0),
	}
}

const (
	BV_LOW_FLAG int8 = iota
	BV_HIGH_FLAG
	BV_NONE_FLAG
)

func (b *VoteAggreator) Append(committee core.Committee, vote *Vote, sigService *crypto.SigService) (int8, []byte, error) {
	if _, ok := b.Authors[vote.Author]; ok {
		return 0, nil, core.ErrOneMoreMessage(vote.MsgType(), vote.Height, 0, vote.Author)
	}
	b.Shares = append(b.Shares, vote.Signature)
	if len(b.Shares) == committee.HightThreshold() {
		data, err := crypto.CombineIntactTSPartial(b.Shares, sigService.ShareKey, vote.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return BV_HIGH_FLAG, nil, err
		}
		return BV_HIGH_FLAG, data, nil
	}
	return BV_NONE_FLAG, nil, nil
}

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
