package backend

import (
	"context"
	"net/http"
)

type Backend interface {
	Run(context.Context) (http.Handler, error)
	Wait() error
	Close() error
}
