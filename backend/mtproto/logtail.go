package mtproto

import "sync"

// lineRing keeps the last lines telemt wrote, so startup and crash errors can
// show them.
type lineRing struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

func newLineRing(size int) *lineRing {
	if size <= 0 {
		size = 1
	}
	return &lineRing{lines: make([]string, size)}
}

func (r *lineRing) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next = 0
	r.full = false
	clear(r.lines)
}

func (r *lineRing) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines[r.next] = line
	r.next = (r.next + 1) % len(r.lines)
	if r.next == 0 {
		r.full = true
	}
}

// tail returns the last n lines, oldest first; n <= 0 returns all of them.
func (r *lineRing) tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := r.next
	oldest := 0
	if r.full {
		count = len(r.lines)
		oldest = r.next
	}
	if n <= 0 || n > count {
		n = count
	}

	out := make([]string, 0, n)
	for i := count - n; i < count; i++ {
		out = append(out, r.lines[(oldest+i)%len(r.lines)])
	}
	return out
}
