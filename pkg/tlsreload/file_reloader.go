package tlsreload

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type fileState struct {
	modTime time.Time
	size    int64
}

// FileReloader watches certificate and key files and reloads them when they change.
type FileReloader struct {
	certPath string
	keyPath  string
	logger   *zap.Logger

	cert      atomic.Value // *tls.Certificate
	mu        sync.Mutex
	certState fileState
	keyState  fileState
}

// NewFileReloader loads the initial certificate/key pair and prepares for reloads.
func NewFileReloader(certPath, keyPath string, logger *zap.Logger) (*FileReloader, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("stat cert file: %w", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	reloader := &FileReloader{
		certPath: certPath,
		keyPath:  keyPath,
		logger:   logger,
		certState: fileState{
			modTime: certInfo.ModTime(),
			size:    certInfo.Size(),
		},
		keyState: fileState{
			modTime: keyInfo.ModTime(),
			size:    keyInfo.Size(),
		},
	}
	reloader.cert.Store(&cert)
	return reloader, nil
}

func (r *FileReloader) maybeReload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return fmt.Errorf("stat cert file: %w", err)
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return fmt.Errorf("stat key file: %w", err)
	}

	newCertState := fileState{modTime: certInfo.ModTime(), size: certInfo.Size()}
	newKeyState := fileState{modTime: keyInfo.ModTime(), size: keyInfo.Size()}

	if newCertState.modTime.Equal(r.certState.modTime) && newCertState.size == r.certState.size &&
		newKeyState.modTime.Equal(r.keyState.modTime) && newKeyState.size == r.keyState.size {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load key pair: %w", err)
	}

	r.cert.Store(&cert)
	r.certState = newCertState
	r.keyState = newKeyState

	if r.logger != nil {
		r.logger.Info("Reloaded TLS certificate files",
			zap.String("certFile", r.certPath),
			zap.String("keyFile", r.keyPath),
			zap.Time("certModTime", newCertState.modTime),
			zap.Time("keyModTime", newKeyState.modTime),
		)
	}
	return nil
}

// GetCertificate reloads certificate/key as needed and returns the current pair.
func (r *FileReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if err := r.maybeReload(); err != nil {
		if r.logger != nil {
			r.logger.Warn("Failed to reload TLS certificate", zap.Error(err))
		}
	}

	value := r.cert.Load()
	if value == nil {
		return nil, fmt.Errorf("no TLS certificate loaded")
	}
	return value.(*tls.Certificate), nil
}
