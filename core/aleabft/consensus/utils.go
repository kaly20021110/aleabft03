package consensus

import "container/heap"

type Item struct {
	value    string // 元素的值
	priority int    // 元素的优先级
}
type PriorityQueue []*Item

func (pq PriorityQueue) Len() int {
	return len(pq)
}

func (pq PriorityQueue) Less(i, j int) bool {
	// 我们希望Pop返回的是最小优先级的元素，因此这里使用小于号
	return pq[i].priority < pq[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	// 向队列中添加一个元素
	item := x.(*Item)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	// 移除并返回队列中的最小优先级元素
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

func (pq *PriorityQueue) Enqueue(value string, priority int) {
	heap.Push(pq, &Item{
		value:    value,
		priority: priority,
	})
}

func (pq *PriorityQueue) Dequeue() string {
	item := heap.Pop(pq).(*Item)
	return item.value
}
