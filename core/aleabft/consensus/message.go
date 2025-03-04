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

type Validator interface {
	Verify(core.Committee) bool
}
type Block struct {
	Proposer core.NodeID
	Batch    pool.Batch
	Height   int64
	PreHash  crypto.Digest
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, Height int64, PreHash crypto.Digest) *Block {
	return &Block{
		Proposer: proposer,
		Batch:    Batch,
		Height:   Height,
		PreHash:  PreHash,
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
	hasher.Add(strconv.AppendInt(nil, b.Height, 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	return hasher.Sum256(nil)
}

// type BlockMessage struct {
// 	Author    core.NodeID
// 	B         *Block
// 	Height    int64
// 	Signature crypto.Signature
// }

// func NewBlockMessage(Author core.NodeID, B *Block, Height int64, sigService *crypto.SigService) (*BlockMessage, error) {
// 	blockMessage := &BlockMessage{
// 		Author: Author,
// 		B:      B,
// 		Height: Height,
// 	}
// 	sig, err := sigService.RequestSignature(blockMessage.Hash())
// 	if err != nil {
// 		return nil, err
// 	}
// 	blockMessage.Signature = sig
// 	return blockMessage, nil
// }

// func (bm *BlockMessage) Verify(committee core.Committee) bool {
// 	pub := committee.Name(bm.Author)
// 	return bm.Signature.Verify(pub, bm.Hash())
// }

// func (bm *BlockMessage) Hash() crypto.Digest {
// 	hasher := crypto.NewHasher()
// 	hasher.Add(strconv.AppendInt(nil, int64(bm.Author), 2))
// 	hasher.Add(strconv.AppendInt(nil, bm.Height, 2))
// 	if bm.B != nil {
// 		d := bm.B.Hash()
// 		hasher.Add(d[:])
// 	}
// 	return hasher.Sum256(nil)
// }

// func (*BlockMessage) MsgType() int {
// 	return BlockMessageType
// }

// type VoteforBlock struct {
// 	Author    core.NodeID
// 	BlockHash crypto.Digest
// 	Height    int64
// 	Signature crypto.Signature
// }

// func NewVoteforBlock(Author core.NodeID, BlockHash crypto.Digest, Height int64, sigService *crypto.SigService) (*VoteforBlock, error) {
// 	vote := &VoteforBlock{
// 		Author:    Author,
// 		BlockHash: BlockHash,
// 		Height:    Height,
// 	}
// 	sig, err := sigService.RequestSignature(vote.Hash())
// 	if err != nil {
// 		return nil, err
// 	}
// 	vote.Signature = sig
// 	return vote, nil
// }

// func (v *VoteforBlock) Verify(committee core.Committee) bool {
// 	pub := committee.Name(v.Author)
// 	return v.Signature.Verify(pub, v.Hash())
// }

// func (v *VoteforBlock) Hash() crypto.Digest {
// 	hasher := crypto.NewHasher()
// 	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
// 	hasher.Add(strconv.AppendInt(nil, v.Height, 2))
// 	hasher.Add(v.BlockHash[:])
// 	return hasher.Sum256(nil)
// }

// func (*VoteforBlock) MsgType() int {
// 	return VoteforBlockType
// }

// type CertForBlockData struct {
// 	Height int64
// 	Hash   crypto.Digest
// }

// type BoltBlock struct {
// 	Proposer     core.NodeID
// 	BoltProposal CertForBlockData
// 	Epoch        int64
// }

// func NewBoltBlock(proposer core.NodeID, BoltProposal CertForBlockData, Epoch int64) *BoltBlock {
// 	return &BoltBlock{
// 		Proposer:     proposer,
// 		BoltProposal: BoltProposal,
// 		Epoch:        Epoch,
// 	}
// }

// func (b *BoltBlock) Encode() ([]byte, error) {
// 	buf := bytes.NewBuffer(nil)
// 	if err := gob.NewEncoder(buf).Encode(b); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// func (b *BoltBlock) Decode(data []byte) error {
// 	buf := bytes.NewBuffer(data)
// 	if err := gob.NewDecoder(buf).Decode(b); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (b *BoltBlock) Hash() crypto.Digest {
// 	hasher := crypto.NewHasher()
// 	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
// 	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
// 	hasher.Add(strconv.AppendInt(nil, int64(b.BoltProposal.Height), 2))
// 	hasher.Add(b.BoltProposal.Hash[:])
// 	return hasher.Sum256(nil)
// }

/**************************** ProposalType ********************************/
type Proposal struct {
	Author        core.NodeID
	B             *Block
	Height        int64
	proof         []byte
	partSignature crypto.Signature
}

func NewProposal(Author core.NodeID, B *Block, Epoch int64, proof []byte, sigService *crypto.SigService) (*Proposal, error) {
	proposal := &Proposal{
		Author: Author,
		B:      B,
		Height: Epoch,
		proof:  proof,
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
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, p.Height, 2))
	hasher.Add(p.proof)
	if p.B != nil {
		d := p.B.Hash()
		hasher.Add(d[:])
	}
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
	Height    int64
	BlockHash crypto.Digest         //对应的block
	Signature crypto.SignatureShare //本轮的部分投票
}

func NewVote(Author, Proposer core.NodeID, Epoch int64, BlockHash crypto.Digest, sigService *crypto.SigService) (*Vote, error) {
	ready := &Vote{
		Author:    Author,
		Proposer:  Proposer,
		Height:    Epoch,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestTsSugnature(ready.Hash())
	if err != nil {
		return nil, err
	}
	ready.Signature = sig
	return ready, nil
}

func (r *Vote) Verify(committee core.Committee) bool {
	//pub := committee.Name(r.Author)
	return r.Signature.Verify(r.Hash())
	//return r.Signature.Verify(pub, r.Hash())
}

func (r *Vote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	//hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Author)))
	hasher.Add(strconv.AppendInt(nil, int64(r.Author), 2))
	hasher.Add(strconv.AppendInt(nil, r.Height, 2))
	hasher.Add(r.BlockHash[:])
	return hasher.Sum256(nil)
}

func (r *Vote) MsgType() int {
	return VoteType
}

/**************************** PrepareType ********************************/

// 用于交换队列中的最新方块值 但是还没加高度区块的证明
type Prepare struct {
	Author    core.NodeID
	Proposer  core.NodeID
	ABAEpoch  int64
	Height    int64            //用于传递高度
	Block     *Block           //提前把block给别人
	proof     []byte           //证明
	Signature crypto.Signature //本轮的部分投票
}

func NewPrepare(Author, Proposer core.NodeID, ABAEpoch int64, Height int64, Block *Block, proof []byte, sigService *crypto.SigService) (*Prepare, error) {
	prepare := &Prepare{
		Author:   Author,
		Proposer: Proposer,
		ABAEpoch: ABAEpoch,
		Height:   Height,
		Block:    Block,
		proof:    proof,
	}
	sig, err := sigService.RequestSignature(prepare.Hash())
	if err != nil {
		return nil, err
	}
	prepare.Signature = sig
	return prepare, nil
}

func (r *Prepare) Verify(committee core.Committee) bool { //验证部分签名的事情我还没有弄懂
	pub := committee.Name(r.Author)
	//return r.Signature.Verify(r.Hash())
	return r.Signature.Verify(pub, r.Hash())
}

func (f *Prepare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(f.proof)
	hasher.Add(strconv.AppendInt(nil, int64(f.Author), 2))
	hasher.Add(strconv.AppendInt(nil, f.ABAEpoch, 2))
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
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Epoch), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Val), 2))
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
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Epoch), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Val), 2))
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
	hasher.Add(strconv.AppendInt(nil, int64(c.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, int64(c.Epoch), 2))
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
	hasher.Add(strconv.AppendInt(nil, int64(h.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Epoch), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Val), 2))
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

/**************************** ABAHaltType ********************************/

type AskVal struct {
	Author    core.NodeID //提出请求的人
	Leader    core.NodeID //想要这个人的对应区块
	Height    int64       //高度
	Signature crypto.Signature
}

func NewAskVal(Author, Leader core.NodeID, Height int64, sigService *crypto.SigService) (*AskVal, error) {
	h := &AskVal{
		Author: Author,
		Leader: Leader,
		Height: Height,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *AskVal) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *AskVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Height)))
	return hasher.Sum256(nil)
}

func (h *AskVal) MsgType() int {
	return AskValType
}

type AnswerVal struct {
	Author    core.NodeID //给予帮助的人
	Leader    core.NodeID //传递给的人
	Height    int64       //高度lock
	B         *Block
	Signature crypto.Signature
}

func NewAnswerVal(Author, Leader core.NodeID, Height int64, block *Block, sigService *crypto.SigService) (*AnswerVal, error) {
	h := &AnswerVal{
		Author: Author,
		Leader: Leader,
		Height: Height,
		B:      block,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *AnswerVal) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *AnswerVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Height)))
	return hasher.Sum256(nil)
}

func (h *AnswerVal) MsgType() int {
	return AnswerValType
}

const (
	ProposalType = iota
	VoteType
	PrepareType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType
	AskValType
	AnswerValType
	//BlockMessageType
	//VoteforBlockType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	ProposalType:  reflect.TypeOf(Proposal{}),
	VoteType:      reflect.TypeOf(Vote{}),
	PrepareType:   reflect.TypeOf(Prepare{}),
	ABAValType:    reflect.TypeOf(ABAVal{}),
	ABAMuxType:    reflect.TypeOf(ABAMux{}),
	CoinShareType: reflect.TypeOf(CoinShare{}),
	ABAHaltType:   reflect.TypeOf(ABAHalt{}),
	AskValType:    reflect.TypeOf(AskVal{}),
	AnswerValType: reflect.TypeOf(AnswerVal{}),
	//BlockMessageType: reflect.TypeOf(BlockMessage{}),
	//VoteforBlockType: reflect.TypeOf(VoteforBlock{}),
}
