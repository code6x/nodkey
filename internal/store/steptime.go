package store

import (
	"context"
	"time"
)

// StepTimer gets the time of each run of a store program (bw or bws):
// the name of the store, the step, such as "bw sync" or "bw get item",
// how long the run took, and whether it failed. It never gets an
// argument, an output or a value. The broker logs it at debug level, so
// that a slow store shows in the journal (DESIGN.md section 21.3).
type StepTimer func(store, step string, took time.Duration, failed bool)

// stepTimerKey is the key of the StepTimer in a context.
type stepTimerKey struct{}

// WithStepTimer returns a copy of ctx with f: each run of a store
// program with that context calls f once, when the run ends.
func WithStepTimer(ctx context.Context, f StepTimer) context.Context {
	return context.WithValue(ctx, stepTimerKey{}, f)
}

// stepTimerOf returns the StepTimer of ctx, or nil.
func stepTimerOf(ctx context.Context) StepTimer {
	f, _ := ctx.Value(stepTimerKey{}).(StepTimer)
	return f
}
