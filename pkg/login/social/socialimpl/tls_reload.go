package socialimpl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/grafana/grafana/pkg/login/social"
)

func (ss *SocialService) readCertificates(name string, info *social.OAuthInfo) (*tls.Config, error) {

	var certs []tls.Certificate

	if info.TlsClientCert != "" || info.TlsClientKey != "" {
		cert, err := tls.LoadX509KeyPair(info.TlsClientCert, info.TlsClientKey)
		if err != nil {
			ss.log.Error("Failed to setup TlsClientCert", "oauth", name, "error", err)
			return nil, fmt.Errorf("failed to setup TlsClientCert: %w", err)
		}

		certs = []tls.Certificate{cert}
	}

	var rootCAs *x509.CertPool
	if info.TlsClientCa != "" {
		caCert, err := os.ReadFile(info.TlsClientCa)
		if err != nil {
			ss.log.Error("Failed to setup TlsClientCa", "oauth", name, "error", err)
			return nil, fmt.Errorf("failed to setup TlsClientCa: %w", err)
		}
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCert)
	}

	return &tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: info.TlsSkipVerify,
		RootCAs:            rootCAs,
	}, nil

}

func (ss *SocialService) GetClientConfig(*tls.ClientHelloInfo) (*tls.Config, error) {
	ss.tlsCerts.certLock.RLock()
	defer ss.tlsCerts.certLock.RUnlock()

	tlsCerts := ss.tlsCerts.certs
	return tlsCerts, nil
}

// fsnotify module can be used to detect file changes and based on the event certs can be reloaded
// since it adds a direct dependency for the optional feature. So that is the reason periodic watching
// of cert files is chosen. If fsnotify is added as direct dependency in future, then the implementation
// can be revisited to align to fsnotify.
func (ss *SocialService) WatchAndUpdateCerts(name string, info *social.OAuthInfo) {
	ticker := time.NewTicker(info.CertWatchInterval)

	for {
		<-ticker.C
		if err := ss.updateCerts(name, info); err != nil {
			ss.log.Error("Not able to reload certificates", "error", err)
		}

	}
}

func getMtime(name string) (time.Time, error) {
	fInfo, err := os.Stat(name)
	if err != nil {
		return time.Time{}, err
	}
	return fInfo.ModTime(), nil
}

func (ss *SocialService) updateCerts(name string, info *social.OAuthInfo) error {
	tlsInfo := &ss.tlsCerts
	cMtime, err := getMtime(info.TlsClientCert)
	if err != nil {
		return err
	}
	kMtime, err := getMtime(info.TlsClientKey)
	if err != nil {
		return err
	}
	caMtime, err := getMtime(info.TlsClientCa)
	if err != nil {
		return err
	}

	if cMtime.Compare(tlsInfo.certMtime) != 0 || kMtime.Compare(tlsInfo.keyMtime) != 0 || caMtime.Compare(caMtime) != 0 {
		certs, err := ss.readCertificates(name, info)
		if err != nil {
			return err
		}
		tlsInfo.certLock.Lock()
		defer tlsInfo.certLock.Unlock()

		tlsInfo.certs = certs
		tlsInfo.certMtime = cMtime
		tlsInfo.keyMtime = kMtime
		tlsInfo.caMtime = caMtime

		ss.log.Info("Server certificates updated", "cMtime", tlsInfo.certMtime, "kMtime", tlsInfo.keyMtime, "catime", tlsInfo.caMtime)
	}
	return nil
}
