// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"strconv"
	"sync"
)

type WorkerFunc func(workerName string, event interface{})

type pooledWorker struct {
	pool     *RoutinePool
	name     string
	quit     chan struct{}    // quit channel
	higher   chan interface{} // High priority event queue
	lower    chan interface{} // Low priority event queue
	workFunc WorkerFunc
}

func (w *pooledWorker) event(v interface{}) {
	if v != nil && w.workFunc != nil {
		var key string
		if w.pool.keyGetter != nil {
			key = w.pool.keyGetter(v)
		}
		if len(key) > 0 {
			incKeyCount(key)
		}
		w.workFunc(w.name, v)
		if len(key) > 0 {
			decKeyCount(key)
		}
	}
}

func (w *pooledWorker) work() {
	defer w.pool.wg.Done()
	for {
		select {
		case <-w.quit:
			return
		case v := <-w.higher:
			// Process high priority event first
			w.event(v)
		default:
			// When there is no high priority event, randomly select event processing
			select {
			case <-w.quit:
				return
			case v := <-w.higher:
				// Processing the waiting high priority events
				w.event(v)
			case v := <-w.lower:
				// Processing the waiting low priority events
				w.event(v)
			}
		}
	}
}

var (
	routinePoolKeyCountMap  map[string]int
	routinePoolKeyCountLock sync.Mutex
)

func init() {
	routinePoolKeyCountMap = make(map[string]int)
}

type RoutinePool struct {
	name      string
	higher    chan interface{} // High priority event queue
	lower     chan interface{} // Low priority event queue
	workers   []*pooledWorker
	keyGetter func(interface{}) string
	lock      sync.Mutex
	started   bool
	quit      chan struct{}
	wg        sync.WaitGroup
}

func NewRoutinePool(name string, routineSize int, queueSize int, workFunc WorkerFunc, keyGetter func(interface{}) string) *RoutinePool {
	ret := &RoutinePool{
		name:      name,
		workers:   make([]*pooledWorker, routineSize),
		keyGetter: keyGetter,
		higher:    make(chan interface{}, queueSize),
		lower:     make(chan interface{}, queueSize),
		started:   false,
		quit:      make(chan struct{}),
		wg:        sync.WaitGroup{},
	}
	for i := 0; i < routineSize; i++ {
		ret.workers[i] = &pooledWorker{
			pool:     ret,
			name:     ret.name + "-" + strconv.Itoa(i+1),
			quit:     ret.quit,
			higher:   ret.higher,
			lower:    ret.lower,
			workFunc: workFunc,
		}
	}
	ret.wg.Add(routineSize)
	return ret
}

func (p *RoutinePool) String() string {
	if p == nil {
		return "RoutinePool<nil>"
	}
	return fmt.Sprintf("RoutinePool{%s Higter:%d Lower:%d Workers:%d}",
		p.name, len(p.higher), len(p.lower), len(p.workers))
}

func (p *RoutinePool) Start() {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.started {
		return
	}
	p.started = true
	for i := 0; i < len(p.workers); i++ {
		go p.workers[i].work()
	}
}

func (p *RoutinePool) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.started {
		return
	}
	close(p.quit)
	p.started = false
	p.wg.Wait()
}

// returns the number of objects in the queue with higher priority
func (p *RoutinePool) HigherLen() int {
	return len(p.higher)
}

// returns the number of objects in the queue with lower priority
func (p *RoutinePool) LowerLen() int {
	return len(p.lower)
}

func incKeyCount(key string) {
	routinePoolKeyCountLock.Lock()
	defer routinePoolKeyCountLock.Unlock()

	c, ok := routinePoolKeyCountMap[key]
	if !ok {
		routinePoolKeyCountMap[key] = 1
	} else {
		routinePoolKeyCountMap[key] = c + 1
	}
}

func decKeyCount(key string) {
	routinePoolKeyCountLock.Lock()
	defer routinePoolKeyCountLock.Unlock()

	c, ok := routinePoolKeyCountMap[key]
	if ok {
		if c <= 1 {
			delete(routinePoolKeyCountMap, key)
		} else {
			routinePoolKeyCountMap[key] = c - 1
		}
	}
}

func KeyCount() map[string]int {
	return routinePoolKeyCountMap
}

func (p *RoutinePool) PostLower(v interface{}) {
	p.lower <- v
}

func (p *RoutinePool) PostHigher(v interface{}) {
	p.higher <- v
}
