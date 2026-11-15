package client

import "context"

type CancelToken struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewCancelToken() *CancelToken {
	ctx, cancel := context.WithCancel(context.Background())
	return &CancelToken{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *CancelToken) Cancel() {
	if t != nil && t.cancel != nil {
		t.cancel()
	}
}

func (t *CancelToken) context() context.Context {
	if t == nil || t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}
