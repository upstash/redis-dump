package redisdump

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/mediocregopher/radix/v3"
)

type TlsHandler struct {
	tls                bool
	caCertPath         string
	certPath           string
	keyPath            string
	insecureSkipVerify bool
}

func NewTlsHandler(tls bool, caCertPath string, certPath string, keyPath string, insecureSkipVerify bool) *TlsHandler {
	return &TlsHandler{
		tls:                tls,
		caCertPath:         caCertPath,
		certPath:           certPath,
		keyPath:            keyPath,
		insecureSkipVerify: insecureSkipVerify,
	}
}

func NewRedisClient(redisURL string, tlsHandler *TlsHandler, redisPassword string, nWorkers int, db string) (*radix.Pool, error) {
	tlsConfig, err := createTlsConfig(tlsHandler)
	if err != nil {
		return nil, err
	}

	customConnFunc := func(network, addr string) (radix.Conn, error) {
		return newRedisConn(network, addr, redisPassword, tlsConfig, db)
	}
	return radix.NewPool("tcp", redisURL, nWorkers, radix.PoolConnFunc(customConnFunc))
}

func NewRedisConn(redisURL string, tlsHandler *TlsHandler, redisPassword string, db string) (radix.Conn, error) {
	tlsConfig, err := createTlsConfig(tlsHandler)
	if err != nil {
		return nil, err
	}
	return newRedisConn("tcp", redisURL, redisPassword, tlsConfig, db)
}

func createTlsConfig(tlsHandler *TlsHandler) (*tls.Config, error) {
	var tlsConfig *tls.Config
	if tlsHandler != nil {
		// ca cert is optional
		var certPool *x509.CertPool
		if tlsHandler.caCertPath != "" {
			pem, err := ioutil.ReadFile(tlsHandler.caCertPath)
			if err != nil {
				return nil, fmt.Errorf("connectionpool: unable to open CA certs: %v", err)
			}

			certPool = x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("connectionpool: failed parsing or CA certs")
			}
		}
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{},
			RootCAs:            certPool,
			InsecureSkipVerify: tlsHandler.insecureSkipVerify,
		}
		if tlsHandler.certPath != "" && tlsHandler.keyPath != "" {
			cert, err := tls.LoadX509KeyPair(tlsHandler.certPath, tlsHandler.keyPath)
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
	}
	return tlsConfig, nil
}

func newRedisConn(network, redisURL string, redisPassword string, tlsConfig *tls.Config, db string) (radix.Conn, error) {
	dialOpts := []radix.DialOpt{
		radix.DialTimeout(5 * time.Minute),
	}
	if redisPassword != "" {
		dialOpts = append(dialOpts, radix.DialAuthPass(redisPassword))
	}
	if tlsConfig != nil {
		dialOpts = append(dialOpts, radix.DialUseTLS(tlsConfig))
	}
	if db != "" {
		dbVal, err := strconv.Atoi(db)
		if err != nil {
			return nil, err
		}
		dialOpts = append(dialOpts, radix.DialSelectDB(dbVal))
	}
	return radix.Dial(network, redisURL, dialOpts...)
}
