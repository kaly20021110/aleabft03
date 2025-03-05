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
	Height   int64
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, Height int64) *Block {
	return &Block{
		Proposer: proposer,
		Batch:    Batch,
		Height:   Height,
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

/**************************** ProposalType ********************************/
type Proposal struct {
	Author        core.NodeID
	B             *Block
	Height        int64
	partSignature crypto.Signature
}

func NewProposal(Author core.NodeID, B *Block, Epoch int64, sigService *crypto.SigService) (*Proposal, error) {
	proposal := &Proposal{
		Author: Author,
		B:      B,
		Height: Epoch,
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
	return r.Signature.Verify(r.Hash())
}

func (r *Vote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(r.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, r.Height, 2))
	hasher.Add(r.BlockHash[:])
	return hasher.Sum256(nil)
}

func (r *Vote) MsgType() int {
	return VoteType
}

type Commitment struct {
	Author    core.NodeID
	C         []byte
	Height    int64
	Signature crypto.Signature
}

func NewCommitment(Author core.NodeID, C []byte, Height int64, sigService *crypto.SigService) (*Commitment, error) {
	commitment := &Commitment{
		Author: Author,
		C:      C,
		Height: Height,
	}
	sig, err := sigService.RequestSignature(commitment.Hash())
	if err != nil {
		return nil, err
	}
	commitment.Signature = sig
	return commitment, nil
}

func (c *Commitment) Verify(committee core.Committee) bool {
	pub := committee.Name(c.Author)
	return c.Signature.Verify(pub, c.Hash())
}

func (c *Commitment) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(c.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(c.Height)))
	hasher.Add(c.C)
	return hasher.Sum256(nil)
}

func (c *Commitment) MsgType() int {
	return CommitmentType
}

type ABAVal struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAVal(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAVal, error) {
	val := &ABAVal{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
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
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAVal) MsgType() int {
	return ABAValType
}

type ABAMux struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAMux(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAMux, error) {
	val := &ABAMux{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
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
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAMux) MsgType() int {
	return ABAMuxType
}

type CoinShare struct {
	Author  core.NodeID
	Leader  core.NodeID
	Epoch   int64
	Round   int64
	InRound int64
	Share   crypto.SignatureShare
}

func NewCoinShare(Author, Leader core.NodeID, Epoch, Round, InRound int64, sigService *crypto.SigService) (*CoinShare, error) {
	coin := &CoinShare{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
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
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.InRound)))
	return hasher.Sum256(nil)
}

func (c *CoinShare) MsgType() int {
	return CoinShareType
}

type ABAHalt struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAHalt(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAHalt, error) {
	h := &ABAHalt{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
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
	hasher.Add([]byte{h.Flag})
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

const (
	ProposalType = iota
	VoteType
	CommitmentType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	ProposalType:   reflect.TypeOf(Proposal{}),
	VoteType:       reflect.TypeOf(Vote{}),
	CommitmentType: reflect.TypeOf(Commitment{}),
	ABAValType:     reflect.TypeOf(ABAVal{}),
	ABAMuxType:     reflect.TypeOf(ABAMux{}),
	CoinShareType:  reflect.TypeOf(CoinShare{}),
	ABAHaltType:    reflect.TypeOf(ABAHalt{}),
}
