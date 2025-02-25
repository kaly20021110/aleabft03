package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"reflect"
	"strconv"
)

const (
	FLAG_YES uint8 = 0
	FLAG_NO  uint8 = 1
)

type Validator interface {
	Verify(core.Committee) bool
}
type Block struct {
	Proposer core.NodeID
	Batch    pool.Batch
	Epoch    int64
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, Epoch int64) *Block {
	return &Block{
		Proposer: proposer,
		Batch:    Batch,
		Epoch:    Epoch,
	}
}
func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}
func (b *Block) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	return hasher.Sum256(nil)
}

/**************************** ProposalType ********************************/
type Proposal struct {
	Author        core.NodeID
	B             *Block
	Epoch         int64
	fullSignature []byte
	partSignature crypto.Signature
}

func NewProposal(Author core.NodeID, B *Block, Epoch int64, sigService *crypto.SigService) (*Proposal, error) {
	proposal := &Proposal{
		Author: Author,
		B:      B,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestSignature(proposal.Hash())
	if err != nil {
		return nil, err
	}
	proposal.partSignature = sig
	return proposal, nil
}

func (p *Proposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.partSignature.Verify(pub, p.Hash())
}

func (p *Proposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(p.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(p.Epoch)))
	d := p.B.Hash()
	hasher.Add(d[:])
	return hasher.Sum256(nil)
}

func (p *Proposal) MsgType() int {
	return ProposalType
}

/**************************** ProposalType ********************************/

/**************************** PrepareType ********************************/
type Vote struct {
	Author    core.NodeID
	Proposer  core.NodeID
	Epoch     int64
	B         *Block                //对应的block
	Signature crypto.SignatureShare //本轮的部分投票
}

func NewVote(Author, Proposer core.NodeID, Epoch int64, B *Block, sigService *crypto.SigService) (*Vote, error) {
	ready := &Vote{
		Author:   Author,
		Proposer: Proposer,
		Epoch:    Epoch,
		B:        B,
	}
	sig, err := sigService.RequestTsSugnature(ready.Hash())
	if err != nil {
		return nil, err
	}
	ready.Signature = sig
	return ready, nil
}

func (r *Vote) Verify(committee core.Committee) bool { //验证部分签名的事情我还没有弄懂
	//pub := committee.Name(r.Author)
	return r.Signature.Verify(r.Hash())
	//return r.Signature.Verify(pub, r.Hash())
}

func (r *Vote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	//hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Proposer)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Epoch)))
	d := r.B.Hash()
	hasher.Add(d[:])
	return hasher.Sum256(nil)
}

func (r *Vote) MsgType() int {
	return VoteType
}

/**************************** PrepareType ********************************/

// 用于交换队列中的最新方块值
type Prepare struct {
	Author    core.NodeID
	Proposer  core.NodeID
	Epoch     int64
	Height    int64                 //用于传递高度
	Signature crypto.SignatureShare //本轮的部分投票
}

func NewPrepare(Author, Proposer core.NodeID, Epoch int64, Height int64, sigService *crypto.SigService) (*Prepare, error) {
	ready := &Prepare{
		Author:   Author,
		Proposer: Proposer,
		Epoch:    Epoch,
		Height:   Height,
	}
	sig, err := sigService.RequestTsSugnature(ready.Hash())
	if err != nil {
		return nil, err
	}
	ready.Signature = sig
	return ready, nil
}

func (r *Prepare) Verify(committee core.Committee) bool { //验证部分签名的事情我还没有弄懂
	//pub := committee.Name(r.Author)
	return r.Signature.Verify(r.Hash())
	//return r.Signature.Verify(pub, r.Hash())
}

func (r *Prepare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Proposer)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Epoch)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Height)))
	return hasher.Sum256(nil)
}

func (r *Prepare) MsgType() int {
	return PrepareType
}

/**************************** ABAValType ********************************/
type ABAVal struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Val       int64
	Signature crypto.Signature
}

func NewABAVal(Author, Leader core.NodeID, Epoch, Round int64, Val int64, sigService *crypto.SigService) (*ABAVal, error) {
	val := &ABAVal{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Round:  Round,
		Val:    Val,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAVal) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Round)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Val)))
	return hasher.Sum256(nil)
}

func (v *ABAVal) MsgType() int {
	return ABAValType
}

/**************************** ABAValType ********************************/

/**************************** ABAMuxType ********************************/
type ABAMux struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Val       int64
	Signature crypto.Signature
}

func NewABAMux(Author, Leader core.NodeID, Epoch, Round int64, Val int64, sigService *crypto.SigService) (*ABAMux, error) {
	val := &ABAMux{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Round:  Round,
		Val:    Val,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAMux) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAMux) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Round)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Val)))
	return hasher.Sum256(nil)
}

func (v *ABAMux) MsgType() int {
	return ABAMuxType
}

/**************************** ABAMuxType ********************************/

/**************************** CoinShareType ********************************/
type CoinShare struct {
	Author core.NodeID
	Leader core.NodeID
	Epoch  int64
	Round  int64
	Share  crypto.SignatureShare
}

func NewCoinShare(Author, Leader core.NodeID, Epoch, Round int64, sigService *crypto.SigService) (*CoinShare, error) {
	coin := &CoinShare{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Round:  Round,
	}
	sig, err := sigService.RequestTsSugnature(coin.Hash())
	if err != nil {
		return nil, err
	}
	coin.Share = sig
	return coin, nil
}

func (c *CoinShare) Verify(committee core.Committee) bool {
	_ = committee.Name(c.Author)
	return c.Share.Verify(c.Hash())
}

func (c *CoinShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Epoch)))
	return hasher.Sum256(nil)
}

func (c *CoinShare) MsgType() int {
	return CoinShareType
}

/**************************** CoinShareType ********************************/

/**************************** ABAHaltType ********************************/
type ABAHalt struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Val       int64
	Signature crypto.Signature
}

func NewABAHalt(Author, Leader core.NodeID, Epoch, Round int64, Val int64, sigService *crypto.SigService) (*ABAHalt, error) {
	h := &ABAHalt{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Round:  Round,
		Val:    Val,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *ABAHalt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *ABAHalt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Epoch)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Round)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Val)))
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

/**************************** ABAHaltType ********************************/

const (
	ProposalType = iota
	VoteType
	PrepareType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	ProposalType:  reflect.TypeOf(Proposal{}),
	VoteType:      reflect.TypeOf(Vote{}),
	PrepareType:   reflect.TypeOf(Prepare{}),
	ABAValType:    reflect.TypeOf(ABAVal{}),
	ABAMuxType:    reflect.TypeOf(ABAMux{}),
	CoinShareType: reflect.TypeOf(CoinShare{}),
	ABAHaltType:   reflect.TypeOf(ABAHalt{}),
}
