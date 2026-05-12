package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func GenerateTLSConfig(priv ed25519.PrivateKey, trustedPubs []ed25519.PublicKey) (*tls.Config, error) {
	pub := priv.Public().(ed25519.PublicKey)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pnet"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Private key PEM
	pkDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkDer})

	cert, err := tls.X509KeyPair(certPem, privPem)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					continue
				}
				peerPub, ok := cert.PublicKey.(ed25519.PublicKey)
				if !ok {
					continue
				}
				for _, trusted := range trustedPubs {
					if peerPub.Equal(trusted) {
						return nil
					}
				}
			}
			return fmt.Errorf("peer not trusted")
		},
		InsecureSkipVerify: true, // We verify manually in VerifyPeerCertificate
	}, nil
}
