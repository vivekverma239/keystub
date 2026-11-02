package limit

import (
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/limit/limittest"
)

func TestContract(t *testing.T) {
	limittest.Run(t, func(now func() time.Time) core.Limiter {
		l := NewMemory()
		l.Now = now
		return l
	})
}
