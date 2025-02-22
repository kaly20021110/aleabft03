package consensus

import (
	"bft/mvba/core"
	"sync"
	"sync/atomic"
)

const (
	ABA_INVOKE = iota
	ABA_HALT
)

type ABABack struct {
	Typ    int
	Epoch  int64
	Round  int64
	Val    int64
	Leader core.NodeID
}

type ABA struct {
	c           *Core
	Epoch       int64
	Round       int64
	maxIndex    int64 //prpare阶段收到的最大整数
	prepareCnt  int64 //prepare计数器
	valMutex    sync.Mutex
	valOdd      map[int64]int64 //奇数
	valEven     map[int64]int64
	valCnt      map[int64]map[int64]int64
	flagMutex   sync.Mutex
	muxFlag     map[int64]struct{}
	yesFlag     map[int64]struct{}
	noFlag      map[int64]struct{}
	muxFinFlag  map[int64]struct{} //已经收到2f+1个mutex不需要再处理mutex
	muxMutex    sync.Mutex
	muxCnt      map[int64]map[int64]int64
	muxOdd      map[int64]int64
	muxEven     map[int64]int64
	halt        atomic.Bool
	abaCallBack chan *ABABack
}

func NewABA(c *Core, Epoch int64, Round int64, abaCallBack chan *ABABack) *ABA {
	return &ABA{
		c:           c,
		Epoch:       Epoch,
		Round:       Round,
		maxIndex:    0,
		prepareCnt:  0,
		valOdd:      make(map[int64]int64),
		valEven:     make(map[int64]int64),
		valCnt:      make(map[int64]map[int64]int64),
		muxCnt:      make(map[int64]map[int64]int64),
		muxOdd:      make(map[int64]int64),
		muxEven:     make(map[int64]int64),
		muxFinFlag:  make(map[int64]struct{}),
		muxFlag:     make(map[int64]struct{}),
		yesFlag:     make(map[int64]struct{}),
		noFlag:      make(map[int64]struct{}),
		abaCallBack: abaCallBack,
	}
}

func (aba *ABA) ProcessABAVal(val *ABAVal) {
	if aba.halt.Load() {
		return
	}
	var cnt int64
	aba.valMutex.Lock()
	aba.valCnt[val.Round][val.Val]++
	cnt = aba.valCnt[val.Round][val.Val]
	aba.valMutex.Unlock()
	if cnt == int64(aba.c.Committee.LowThreshold()) {
		aba.valMutex.Lock()
		if val.Val%2 == 1 {
			aba.valOdd[val.Round] = val.Val
		} else {
			aba.valEven[val.Round] = val.Val
		}
		aba.valMutex.Unlock()
		aba.abaCallBack <- &ABABack{
			Typ:    ABA_INVOKE,
			Epoch:  aba.Epoch,
			Round:  aba.Round,
			Val:    val.Val,
			Leader: val.Leader,
		}
	} else if cnt == int64(aba.c.Committee.HightThreshold()) {
		aba.flagMutex.Lock()
		defer aba.flagMutex.Unlock()
		if _, ok := aba.muxFlag[val.Round]; !ok { //mux消息只发一次
			aba.muxFlag[val.Round] = struct{}{}
			mux, _ := NewABAMux(aba.c.Name, val.Leader, val.Epoch, val.Round, val.Val, aba.c.SigService)
			aba.c.Transimtor.Send(aba.c.Name, core.NONE, mux)
			aba.c.Transimtor.RecvChannel() <- mux
		}
	} else if cnt == int64(aba.c.Committee.Size()) { //加快进程，如果收到3f+1个直接提交了就,直接发送ABAhalt消息，提醒别人结束
		temp, _ := NewABAHalt(aba.c.Name, val.Leader, aba.Epoch, aba.Round, val.Val, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, temp)
		aba.c.Transimtor.RecvChannel() <- temp
	}
}

func (aba *ABA) ProcessABAMux(mux *ABAMux) {
	if aba.halt.Load() {
		return
	}
	aba.flagMutex.Lock()
	if _, ok := aba.muxFinFlag[mux.Round]; ok {
		aba.flagMutex.Unlock()
		return
	}
	aba.flagMutex.Unlock()
	var muxOddcnt, muxEvencnt int64
	var valeven, valodd int64
	aba.valMutex.Lock()
	valeven = aba.valEven[mux.Round]
	valodd = aba.valOdd[mux.Round]
	aba.valMutex.Unlock()
	aba.muxMutex.Lock()
	if (mux.Val == valeven) || (mux.Val == valodd) {
		if mux.Val%2 == 1 {
			aba.muxOdd[mux.Round]++
			muxOddcnt = aba.muxOdd[mux.Round]
		} else {
			aba.muxEven[mux.Round]++
			muxEvencnt = aba.muxOdd[mux.Round]
		}
	}
	aba.muxMutex.Unlock()
	aba.muxCnt[mux.Round][mux.Val]++

	var Oddvalue, Evenvalue int64
	var Oddvaluecnt, Evenvaluecnt int64
	aba.valMutex.Lock()
	Oddvalue, Evenvalue = aba.valOdd[mux.Round], aba.valEven[mux.Round]
	Oddvaluecnt, Evenvaluecnt = aba.valCnt[mux.Round][Oddvalue], aba.valCnt[mux.Round][Evenvalue]
	aba.valMutex.Unlock()

	var flag bool
	th := int64(aba.c.Committee.HightThreshold())

	aba.flagMutex.Lock()
	if _, ok := aba.muxFinFlag[mux.Round]; ok { //double check
		aba.flagMutex.Unlock()
		return
	}
	if muxOddcnt+muxEvencnt >= th {
		if Oddvaluecnt >= th && Evenvaluecnt >= th {
			if muxOddcnt > 0 {
				aba.yesFlag[mux.Round] = struct{}{}
				aba.muxFinFlag[mux.Round] = struct{}{}
				flag = true
			}
			if muxEvencnt > 0 {
				aba.noFlag[mux.Round] = struct{}{}
				aba.muxFinFlag[mux.Round] = struct{}{}
				flag = true
			}
		} else if Oddvaluecnt >= th && muxOddcnt >= th {
			aba.yesFlag[mux.Round] = struct{}{}
			aba.muxFinFlag[mux.Round] = struct{}{}
			flag = true
		} else if Evenvaluecnt >= th && muxEvencnt >= th {
			aba.noFlag[mux.Round] = struct{}{}
			aba.muxFinFlag[mux.Round] = struct{}{}
			flag = true
		}
	}
	aba.flagMutex.Unlock()
	if flag { //only once call
		coinShare, _ := NewCoinShare(aba.c.Name, mux.Leader, mux.Epoch, mux.Round, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, coinShare)
		aba.c.Transimtor.RecvChannel() <- coinShare
	}

}

func (aba *ABA) ProcessCoin(inRound int64, coin int64, Leader core.NodeID) {
	aba.flagMutex.Lock()
	defer aba.flagMutex.Unlock()
	_, okYes := aba.yesFlag[inRound]
	_, okNo := aba.noFlag[inRound]
	var nextinput, nextodd, nexteven int64

	aba.valMutex.Lock()
	if (coin % 2) == (aba.valEven[inRound] % 2) {
		nextinput = aba.valEven[inRound]
	} else {
		nextinput = aba.valOdd[inRound]
	}
	nextodd = aba.valEven[inRound]
	nexteven = aba.valOdd[inRound]
	aba.valMutex.Unlock()

	if (okYes && okNo) || (!okYes && !okNo) { //next round with coin
		abaVal, _ := NewABAVal(aba.c.Name, Leader, aba.Epoch, inRound+1, nextinput, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, abaVal)
		aba.c.Transimtor.RecvChannel() <- abaVal
	} else if (okYes && coin == 0) || (okNo && coin == 1) {
		halt, _ := NewABAHalt(aba.c.Name, Leader, aba.Epoch, inRound, nextinput, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, halt)
		aba.c.Transimtor.RecvChannel() <- halt
	} else { // next round with self
		var abaVal *ABAVal
		if okYes {
			abaVal, _ = NewABAVal(aba.c.Name, Leader, aba.Epoch, inRound+1, nextodd, aba.c.SigService)
		} else if okNo {
			abaVal, _ = NewABAVal(aba.c.Name, Leader, aba.Epoch, inRound+1, nexteven, aba.c.SigService)
		}
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, abaVal)
		aba.c.Transimtor.RecvChannel() <- abaVal
	}
}

func (aba *ABA) ProcessHalt(halt *ABAHalt) {
	aba.flagMutex.Lock()
	defer aba.flagMutex.Unlock()
	if aba.halt.Load() {
		return
	}
	aba.halt.Store(true)
	temp, _ := NewABAHalt(aba.c.Name, halt.Leader, aba.Epoch, halt.Round, halt.Val, aba.c.SigService)
	aba.c.Transimtor.Send(aba.c.Name, core.NONE, temp)
	aba.c.Transimtor.RecvChannel() <- temp

	aba.abaCallBack <- &ABABack{
		Typ:    ABA_HALT,
		Epoch:  halt.Epoch,
		Round:  halt.Round,
		Val:    halt.Val,
		Leader: halt.Leader,
	}
}
