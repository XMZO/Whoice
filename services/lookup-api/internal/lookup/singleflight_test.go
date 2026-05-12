package lookup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestSingleflightCoalescesConcurrentCalls(t *testing.T) {
	group := newSingleflight()
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})

	fn := func(context.Context) (*model.LookupResult, error) {
		calls.Add(1)
		close(started)
		<-release
		return &model.LookupResult{NormalizedQuery: "example.com"}, nil
	}

	var wg sync.WaitGroup
	results := make(chan *model.LookupResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := group.Do(context.Background(), "same", fn)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results <- result
		}()
	}

	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Fatalf("calls: got %d want 1", got)
	}
	for result := range results {
		if result.NormalizedQuery != "example.com" {
			t.Fatalf("unexpected result: %#v", result)
		}
	}
}
