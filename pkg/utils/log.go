package utils

import (
	"github.com/ory/fosite"
	"go.uber.org/zap"
)

func Err(err error) []zap.Field {
	if err, ok := err.(*fosite.RFC6749Error); ok {
		return []zap.Field{
			zap.String("error", err.ErrorField),
			zap.String("description", err.DescriptionField),
			zap.String("hint", err.HintField),
			zap.Int("code", err.CodeField),
			zap.String("debug", err.DebugField),
		}
	} else {
		return []zap.Field{zap.Error(err)}
	}
}
