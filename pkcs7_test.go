package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
	expected := []byte("We the People")
	if bytes.Compare(p7.Content, expected) != 0 {
		t.Errorf("Signed content does not match.\n\tExpected:%s\n\tActual:%s", expected, p7.Content)

	}
}

func TestVerifyAuthenticode(t *testing.T) {
	fixture := UnmarshalTestFixture(AuthenticodeTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyEC2(t *testing.T) {
	fixture := UnmarshalTestFixture(EC2IdentityDocumentFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Certificates = []*x509.Certificate{fixture.Certificate}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyAppStore(t *testing.T) {
	fixture := UnmarshalTestFixture(AppStoreRecieptFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if bytes.Compare(content, expected) != 0 {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}

func TestSign(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	for _, testDetach := range []bool{false, true} {
		toBeSigned, err := NewSignedData(content)
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		if testDetach {
			t.Log("Testing detached signature")
			toBeSigned.Detach()
		} else {
			t.Log("Testing attached signature")
		}
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
		p7, err := Parse(signed)
		if err != nil {
			t.Fatalf("Cannot parse our signed data: %s", err)
		}
		if testDetach {
			p7.Content = content
		}
		if bytes.Compare(content, p7.Content) != 0 {
			t.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		}
		if err := p7.Verify(); err != nil {
			t.Errorf("Cannot verify our signed data: %s", err)
		}
	}
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate()
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestOpenSSLVerifyDetachedSignature(t *testing.T) {
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil)
	if err != nil {
		t.Fatalf("Cannot generate root cert: %s", err)
	}
	signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", rootCert)
	if err != nil {
		t.Fatalf("Cannot generate signer cert: %s", err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddSigner(signerCert.Certificate, signerCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.Detach()
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}

	// write the root cert to a temp file
	tmpRootCertFile, err := ioutil.TempFile("", "pkcs7TestRootCA")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpRootCertFile.Name()) // clean up
	fd, err := os.OpenFile(tmpRootCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Certificate.Raw})
	fd.Close()

	// write the signature to a temp file
	tmpSignatureFile, err := ioutil.TempFile("", "pkcs7Signature")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpSignatureFile.Name()) // clean up
	ioutil.WriteFile(tmpSignatureFile.Name(), signed, 0755)

	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "pkcs7Content")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpContentFile.Name()) // clean up
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify",
		"-in", tmpSignatureFile.Name(), "-inform", "DER",
		"-content", tmpContentFile.Name(),
		"-CAfile", tmpRootCertFile.Name())
	out, err := opensslCMD.Output()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("openssl command failed with %s", err)
	}
}

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode

		plaintext := []byte("Hello Secret World!")
		cert, err := createTestCertificate()
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
		if err != nil {
			t.Fatal(err)
		}
		p7, err := Parse(encrypted)
		if err != nil {
			t.Fatalf("cannot Parse encrypted result: %s", err)
		}
		result, err := p7.Decrypt(cert.Certificate, cert.PrivateKey)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if bytes.Compare(plaintext, result) != 0 {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if bytes.Compare(test.Expected, padded) != 0 {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func createTestCertificate() (certKeyPair, error) {
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil)
	if err != nil {
		return certKeyPair{}, err
	}
	fmt.Println("Created root cert")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate.Raw})
	pair, err := createTestCertificateByIssuer("Jon Snow", signer)
	if err != nil {
		return certKeyPair{}, err
	}
	fmt.Println("Created signer cert")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate.Raw})
	return *pair, nil
}

func createTestCertificateByIssuer(name string, issuer *certKeyPair) (*certKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	var issuerCert *x509.Certificate
	var issuerKey crypto.PrivateKey
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = issuer.PrivateKey
	} else {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		issuerCert = &template
		issuerKey = priv
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{
		Certificate: leaf,
		PrivateKey:  priv,
	}, nil
}

type TestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func UnmarshalTestFixture(testPEMBlock string) TestFixture {
	var result TestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		case "PRIVATE KEY":
			result.PrivateKey, _ = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		}
	}

	return result
}

func MarshalTestFixture(t TestFixture, w io.Writer) {
	if t.Input != nil {
		pem.Encode(w, &pem.Block{Type: "PKCS7", Bytes: t.Input})
	}
	if t.Certificate != nil {
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: t.Certificate.Raw})
	}
	if t.PrivateKey != nil {
		pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t.PrivateKey)})
	}
}

var SignedTestFixture = `
-----BEGIN PKCS7-----
MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B
BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG
SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh
cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB
Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP
J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF
a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw
DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8
zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+
L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy
axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD
bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI
hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4
LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG
SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX
iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM
FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1TCCAUCgAwIBAgIEabg3LTALBgkqhkiG9w0BAQswKTEQMA4GA1UEChMHQWNt
ZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTE1MDUwNjA0MjQ0OFoXDTE2
MDUwNjA0MjQ0OFowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNu
b3cwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKq/rUxeJmT+azMJV6dcvnK0
bRabi1xdc7wWYmDHyLwB8KNbWvBNSHMhDydYyIijHMG83qOpAJmcyCUQk3s6vY8F
1LCm0E73Hzh/R5o1JlwUVhV2WKELPzmmhWuOXXh5sBHjEJLklhLWIlSimV7STrX5
SiE9zK8iRA4oiLTJHcm1AgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIAoDALBgkqhkiG
9w0BAQsDgYEAytRMHmVkS/n+2fidJFc2PM16bXAWleC3+cBmSSyVVIKd926SzaU9
8mnUvvl0CfnL7Vt8AA0MwUkzHbsjhfGX/i+04460Nvhdh2zWylIQUCrncU37/XSR
3Smw/p4AgnUCWJCMtmHsbKDRtAvJ0JIIMmsWXfyevcQ1ceqbot0o/LA=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQCqv61MXiZk/mszCVenXL5ytG0Wm4tcXXO8FmJgx8i8AfCjW1rw
TUhzIQ8nWMiIoxzBvN6jqQCZnMglEJN7Or2PBdSwptBO9x84f0eaNSZcFFYVdlih
Cz85poVrjl14ebAR4xCS5JYS1iJUople0k61+UohPcyvIkQOKIi0yR3JtQIDAQAB
AoGBAIPLCR9N+IKxodq11lNXEaUFwMHXc1zqwP8no+2hpz3+nVfplqqubEJ4/PJY
5AgbJoIfnxVhyBXJXu7E+aD/OPneKZrgp58YvHKgGvvPyJg2gpC/1Fh0vQB0HNpI
1ZzIZUl8ZTUtVgtnCBUOh5JGI4bFokAqrT//Uvcfd+idgxqBAkEA1ZbP/Kseld14
qbWmgmU5GCVxsZRxgR1j4lG3UVjH36KXMtRTm1atAam1uw3OEGa6Y3ANjpU52FaB
Hep5rkk4FQJBAMynMo1L1uiN5GP+KYLEF5kKRxK+FLjXR0ywnMh+gpGcZDcOae+J
+t1gLoWBIESH/Xt639T7smuSfrZSA9V0EyECQA8cvZiWDvLxmaEAXkipmtGPjKzQ
4PsOtkuEFqFl07aKDYKmLUg3aMROWrJidqsIabWxbvQgsNgSvs38EiH3wkUCQQCg
ndxb7piVXb9RBwm3OoU2tE1BlXMX+sVXmAkEhd2dwDsaxrI3sHf1xGXem5AimQRF
JBOFyaCnMotGNioSHY5hAkEAxyXcNixQ2RpLXJTQZtwnbk0XDcbgB+fBgXnv/4f3
BCvcu85DqJeJyQv44Oe1qsXEX9BfcQIOVaoep35RPlKi9g==
-----END PRIVATE KEY-----`

// echo -n "This is a test" > test.txt
// openssl cms -encrypt -in test.txt cert.pem
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBGgYJKoZIhvcNAQcDoIIBCzCCAQcCAQAxgcwwgckCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMA0GCSqGSIb3
DQEBAQUABIGAyFz7bfI2noUs4FpmYfztm1pVjGyB00p9x0H3gGHEYNXdqlq8VG8d
iq36poWtEkatnwsOlURWZYECSi0g5IAL0U9sj82EN0xssZNaK0S5FTGnB3DPvYgt
HJvcKq7YvNLKMh4oqd17C6GB4oXyEBDj0vZnL7SUoCAOAWELPeC8CTUwMwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhEowTkot3a7oAQFD//J/IhFnk+JbkH7HZQFA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

var EC2IdentityDocumentFixture = `
-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA
JIAEggGmewogICJwcml2YXRlSXAiIDogIjE3Mi4zMC4wLjI1MiIsCiAgImRldnBh
eVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1
cy1lYXN0LTFhIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3Rh
bmNlSWQiIDogImktZjc5ZmU1NmMiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVs
bCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIg
OiAiMTIxNjU5MDE0MzM0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwK
ICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDhUMDM6MDE6MzhaIiwKICAiYXJj
aGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJy
YW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAA
AAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5n
dG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2Vi
IFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDgwMzAxNDRaMCMG
CSqGSIb3DQEJBDEWBBTuUc28eBXmImAautC+wOjqcFCBVjAJBgcqhkjOOAQDBC8w
LQIVAKA54NxGHWWCz5InboDmY/GHs33nAhQ6O/ZI86NwjA9Vz3RNMUJrUPU5tAAA
AAAAAA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

var AppStoreRecieptFixture = `
-----BEGIN PKCS7-----
MIITtgYJKoZIhvcNAQcCoIITpzCCE6MCAQExCzAJBgUrDgMCGgUAMIIDVwYJKoZI
hvcNAQcBoIIDSASCA0QxggNAMAoCAQgCAQEEAhYAMAoCARQCAQEEAgwAMAsCAQEC
AQEEAwIBADALAgEDAgEBBAMMATEwCwIBCwIBAQQDAgEAMAsCAQ8CAQEEAwIBADAL
AgEQAgEBBAMCAQAwCwIBGQIBAQQDAgEDMAwCAQoCAQEEBBYCNCswDAIBDgIBAQQE
AgIAjTANAgENAgEBBAUCAwFgvTANAgETAgEBBAUMAzEuMDAOAgEJAgEBBAYCBFAy
NDcwGAIBAgIBAQQQDA5jb20uemhpaHUudGVzdDAYAgEEAgECBBCS+ZODNMHwT1Nz
gWYDXyWZMBsCAQACAQEEEwwRUHJvZHVjdGlvblNhbmRib3gwHAIBBQIBAQQU4nRh
YCEZx70Flzv7hvJRjJZckYIwHgIBDAIBAQQWFhQyMDE2LTA3LTIzVDA2OjIxOjEx
WjAeAgESAgEBBBYWFDIwMTMtMDgtMDFUMDc6MDA6MDBaMD0CAQYCAQEENbR21I+a
8+byMXo3NPRoDWQmSXQF2EcCeBoD4GaL//ZCRETp9rGFPSg1KekCP7Kr9HAqw09m
MEICAQcCAQEEOlVJozYYBdugybShbiiMsejDMNeCbZq6CrzGBwW6GBy+DGWxJI91
Y3ouXN4TZUhuVvLvN1b0m5T3ggQwggFaAgERAgEBBIIBUDGCAUwwCwICBqwCAQEE
AhYAMAsCAgatAgEBBAIMADALAgIGsAIBAQQCFgAwCwICBrICAQEEAgwAMAsCAgaz
AgEBBAIMADALAgIGtAIBAQQCDAAwCwICBrUCAQEEAgwAMAsCAga2AgEBBAIMADAM
AgIGpQIBAQQDAgEBMAwCAgarAgEBBAMCAQEwDAICBq4CAQEEAwIBADAMAgIGrwIB
AQQDAgEAMAwCAgaxAgEBBAMCAQAwGwICBqcCAQEEEgwQMTAwMDAwMDIyNTMyNTkw
MTAbAgIGqQIBAQQSDBAxMDAwMDAwMjI1MzI1OTAxMB8CAgaoAgEBBBYWFDIwMTYt
MDctMjNUMDY6MjE6MTFaMB8CAgaqAgEBBBYWFDIwMTYtMDctMjNUMDY6MjE6MTFa
MCACAgamAgEBBBcMFWNvbS56aGlodS50ZXN0LnRlc3RfMaCCDmUwggV8MIIEZKAD
AgECAggO61eH554JjTANBgkqhkiG9w0BAQUFADCBljELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkFwcGxlIEluYy4xLDAqBgNVBAsMI0FwcGxlIFdvcmxkd2lkZSBEZXZl
bG9wZXIgUmVsYXRpb25zMUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNTExMTMw
MjE1MDlaFw0yMzAyMDcyMTQ4NDdaMIGJMTcwNQYDVQQDDC5NYWMgQXBwIFN0b3Jl
IGFuZCBpVHVuZXMgU3RvcmUgUmVjZWlwdCBTaWduaW5nMSwwKgYDVQQLDCNBcHBs
ZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczETMBEGA1UECgwKQXBwbGUg
SW5jLjELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQClz4H9JaKBW9aH7SPaMxyO4iPApcQmyz3Gn+xKDVWG/6QC15fKOVRtfX+yVBid
xCxScY5ke4LOibpJ1gjltIhxzz9bRi7GxB24A6lYogQ+IXjV27fQjhKNg0xbKmg3
k8LyvR7E0qEMSlhSqxLj7d0fmBWQNS3CzBLKjUiB91h4VGvojDE2H0oGDEdU8zeQ
uLKSiX1fpIVK4cCc4Lqku4KXY/Qrk8H9Pm/KwfU8qY9SGsAlCnYO3v6Z/v/Ca/Vb
XqxzUUkIVonMQ5DMjoEC0KCXtlyxoWlph5AQaCYmObgdEHOwCl3Fc9DfdjvYLdmI
HuPsB8/ijtDT+iZVge/iA0kjAgMBAAGjggHXMIIB0zA/BggrBgEFBQcBAQQzMDEw
LwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtd3dkcjA0
MB0GA1UdDgQWBBSRpJz8xHa3n6CK9E31jzZd7SsEhTAMBgNVHRMBAf8EAjAAMB8G
A1UdIwQYMBaAFIgnFwmpthhgi+zruvZHWcVSVKO3MIIBHgYDVR0gBIIBFTCCAREw
ggENBgoqhkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9u
IHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5j
ZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25k
aXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0
aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3
LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wDgYDVR0PAQH/BAQDAgeA
MBAGCiqGSIb3Y2QGCwEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQANphvTLj3jWysH
bkKWbNPojEMwgl/gXNGNvr0PvRr8JZLbjIXDgFnf4+LXLgUUrA3btrj+/DUufMut
F2uOfx/kd7mxZ5W0E16mGYZ2+FogledjjA9z/Ojtxh+umfhlSFyg4Cg6wBA3Lbmg
BDkfc7nIBf3y3n8aKipuKwH8oCBc2et9J6Yz+PWY4L5E27FMZ/xuCk/J4gao0pfz
p45rUaJahHVl0RYEYuPBX/UIqc9o2ZIAycGMs/iNAGS6WGDAfK+PdcppuVsq1h1o
bphC9UynNxmbzDscehlD86Ntv0hgBgw2kivs3hi1EdotI9CO/KBpnBcbnoB7OUdF
MGEvxxOoMIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjEL
MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxl
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENB
MB4XDTEzMDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVT
MRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUg
RGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERl
dmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0
U3rOfGOAYXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkV
CBmsqtsqMu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8
V25nNYB2NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHl
d0WNUEi6Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1q
arunFjVg0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGj
gaYwgaMwHQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQF
MAMBAf8wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcw
JTAjoCGgH4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/
BAQDAgGGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Z
viz1smwvj+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/N
w0Uwj6ODDc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJ
TleMa1s8Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1V
AKmuu0swruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur
+cmV6U/kTecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxR
pVzscYqCtGwPDBUfMIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQsw
CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUg
Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0Ew
HhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne
+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjcz
y8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQ
Z48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCS
C7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINB
hzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIB
djAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9Bp
R5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/
CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcC
ARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCB
thqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz
c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJk
IHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5
IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3
DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizU
sZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJ
fBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr
1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltk
wGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIq
xw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUhMYIByzCCAccCAQEwgaMwgZYxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBX
b3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29y
bGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkCCA7rV4fnngmNMAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEggEAasPtnide
NWyfUtewW9OSgcQA8pW+5tWMR0469cBPZR84uJa0gyfmPspySvbNOAwnrwzZHYLa
ujOxZLip4DUw4F5s3QwUa3y4BXpF4J+NSn9XNvxNtnT/GcEQtCuFwgJ0o3F0ilhv
MTHrwiwyx/vr+uNDqlORK8lfK+1qNp+A/kzh8eszMrn4JSeTh9ZYxLHE56WkTQGD
VZXl0gKgxSOmDrcp1eQxdlymzrPv9U60wUJ0bkPfrU9qZj3mJrmrkQk61JTe3j6/
QfjfFBG9JG2mUmYQP1KQ3SypGHzDW8vngvsGu//tNU0NFfOqQu4bYU4VpQl0nPtD
4B85NkrgvQsWAQ==
-----END PKCS7-----`

var AuthenticodeTestFixture = `
-----BEGIN PKCS7-----
MIInIQYJKoZIhvcNAQcCoIInEjCCJw4CAQExDzANBglghkgBZQMEAgEFADBcBgor
BgEEAYI3AgEEoE4wTDAXBgorBgEEAYI3AgEPMAkDAQCgBKICgAAwMTANBglghkgB
ZQMEAgEFAAQgAH9MlRJXE7ESCT4hZj4tI+PBrpzktd4NWKKXMyM2otigggssMIIF
FDCCA/ygAwIBAgITMwAAACtLebNpTRIRhwABAAAAKzANBgkqhkiG9w0BAQsFADCB
gTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMi
TWljcm9zb2Z0IENvcnBvcmF0aW9uIFVFRkkgQ0EgMjAxMTAeFw0xODA3MDMyMDUz
MDFaFw0xOTA3MjYyMDUzMDFaMIGGMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
cnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgV2luZG93cyBVRUZJIERyaXZl
ciBQdWJsaXNoZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvdKwb
/nA6xOyJrEv4ooawjt0TKaVPYqrgbJYSJvc3KVdEhVlG+ruFyDOE+gNrAFwWd2n/
kr6WRjgiAi3YZxN6f88IxpBORWRWxQH1PRHO1/DbWxuvkDNDo004C36x/+P2KegW
6XtLaC+bGMOkz3Gr5aupL3mFCwYZ9BT1OeVXzCvgW56IWjnZdsLjMmWSqCaSweOP
mUORFMbxb9HqNMk2bNXCeHGN/vJOTqrRFB5TzM8d7myYzCy3I71Zznp5edhJ17Pc
Cff1sTevAsG6u5yvseFWvhuN4xqjYh9iCPpeeJPZF5kL2Id5WvbYoXdlK1Mae6tn
hlIT/anAvqUySWFFAgMBAAGjggF8MIIBeDAfBgNVHSUEGDAWBgorBgEEAYI3UAIB
BggrBgEFBQcDAzAdBgNVHQ4EFgQUXcTMqyC8vQlKJsRMb8/AmZ5aD3swUAYDVR0R
BEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBS
aWNvMRYwFAYDVQQFEw0yMjk5MTErNDM3OTU2MB8GA1UdIwQYMBaAFBOtv0MJvYJw
nIzVTzFu1SKYihvUMFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly93d3cubWljcm9z
b2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvclVFRkNBMjAxMV8yMDExLTA2LTI3LmNy
bDBgBggrBgEFBQcBAQRUMFIwUAYIKwYBBQUHMAKGRGh0dHA6Ly93d3cubWljcm9z
b2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29yVUVGQ0EyMDExXzIwMTEtMDYtMjcu
Y3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFS3cfPO8qOb7UpD
WJ2QTBYr5/gbGU8Chzt00ByoiVUzMJZL5T/dX3bTRtIp4mpcjlOF5Lsxb/wHMXu+
nh61jCa2m3k8SIAaZ8da6REOaw1XBOGU8BSFR4rQiU6nvf0FOlS8TXF5uRApC9Mg
BuHT5nDmLJAfz2iPWDHRRd3ErMgnwu3mpv72ElNM30U8D8oxXhx8bZ8adBjt3VOZ
ZlfgsMrMqu5eV8VLB84zuFRH997pn8IieFxMRZfdqQWZ2utGryN7sslxT4s5ynMm
0c61dX0SUDS2Sb78vx9mbG4SRr/S2q6Wti7KqUIl4OSyYTO5j9ENTIH9/e+61n/7
ZFKQ3a4wggYQMIID+KADAgECAgphCNPEAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGR
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJN
aWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9v
dDAeFw0xMTA2MjcyMTIyNDVaFw0yNjA2MjcyMTMyNDVaMIGBMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29y
cG9yYXRpb24gVUVGSSBDQSAyMDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEApQhsTMdFCWpLDKTAh38GdQxDAVRk4BZ/B+2SfQuyc78MCsZKRWGgxRYt
ltP1K6D7TUmbQYCQPLlU/ea80Z3EpBiKf0GKXFmDaDK7jEfJ7nG8IU+ainz/RD+N
jzKyJkiudbXuyUweShl+5IKaHXh3TQywvfYP0xbTvPorpVE4XfX7utt4Atv/7Aob
ltWDuBkT6bbAe0B74R8oJ8n671ZeHOZ+lH7A8ESyeTnl2rJii02/OHDiaCQUyTOk
CDfVWGle03ztwQRTCOdOsCqHYwhhb2MVWeqyK3nXDGFnilv9Xq2Hf7qGZ09xWBIi
BCIizovvVHEAzlA1WHaVCO5qsaIB1QIDAQABo4IBdjCCAXIwEgYJKwYBBAGCNxUB
BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU+MFrt393U0rzJTcdTqEmew8gcIAwHQYD
VR0OBBYEFBOtv0MJvYJwnIzVTzFu1SKYihvUMBkGCSsGAQQBgjcUAgQMHgoAUwB1
AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
FEVmUkPhflgRv9ZOniNVCDs6ImqoMFwGA1UdHwRVMFMwUaBPoE2GS2h0dHA6Ly9j
cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvclRoaVBhck1h
clJvb18yMDEwLTEwLTA1LmNybDBgBggrBgEFBQcBAQRUMFIwUAYIKwYBBQUHMAKG
RGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29yVGhpUGFy
TWFyUm9vXzIwMTAtMTAtMDUuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA1CEL/MMzO
93YMrRBoWDUpRjJ2J3zvEkEnQhtKqm2BOEhZE1Xz6Vg0phYLgqpdrYLagINBBo+0
HfIDufMaXRvxUJD5s1WEQigcIL2yrlEUxcCsl5UhHJDbD/x3npVzkYjKvb1SuQVQ
Dd9XnqBh7Q3lbSXZQA8XQMjOo0rCTa+aEh0IVI+9x7y5Kz1JKx8y/GohaU+byH5C
NPw2BheLjyBAwLOaJXUnzckDo/Zd0ec2VHq5ULXTEtEHv7t039wej4DV7Rj0LxQW
ay/eZoywI+XHhNjt6sEzgq1WSxgt8WiVB83P8HLwrrvdhoWYLCFMMyvwD0rwaIe1
klUydaFqgmo8oyURpO2t1wSuy9hAWaCE0ZVMYpEiGnQdjD1HDkSm5LCbNDWx+rZT
qCyB7KQFcciduLroG0Rm5EdUDo5Wf7OfFpiyhtBoPpAjtS9ej1CFjcaNgl9BofQu
DeCZ0mx15LZptSGG+gfR9uJN0dqtLHdTHiUyN8dsUnKVhrDxNWFqGfWyO4FQVqYy
Lf6iiflChicYVaGCylqb+DCYVBSmR5YlL8gm5EGUGlwCP+WW44VbPD4/u0cWclXi
JSKx2XvnAwYqo/cekEbDAA3WGYnjDjUnYgNxFabv0CegoFk3YPg4lLjgeHD4ukyG
h5T24K4CRe5lwrajfmkWdQeSm/WmvFmDWDGCG2gwghtkAgEBMIGZMIGBMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3Nv
ZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDExAhMzAAAAK0t5s2lNEhGHAAEAAAAr
MA0GCWCGSAFlAwQCAQUAoIHGMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD2Ys4/
5cMC/ycG6FCXXgwN9O1GwFzoIuWI6SY3DXoxxzBaBgorBgEEAYI3AgEMMUwwSqAc
gBoAQwBhAG4AbwBuAGkAYwBhAGwAIABMAHQAZKEqgChodHRwczovL3d3dy5taWNy
b3NvZnQuY29tL2VuLXVzL3dpbmRvd3MgMA0GCSqGSIb3DQEBAQUABIIBABcyfTbS
OqlusWJgyjtsODEihEErktQNKoVdeZNYPGxgekKg+KikaePmd+1igsD8j4XPDnqH
1qWDT3QmAR9qrx5EcYDMdzoIRy/re6a4veQyLZB/gEbNmeWkJhGPiyD5Iu+3kunv
2d1qQMLuRBVl1MREM55Yk0IKS/gD3dzWWfbuJ5U3ahXvCTiue5o4tZxSYiDhRXZX
CohUjrj7qaNXblZvFJ5fnyQG9RYwKhiBwZYS7ykLZufsIgkTqZCcYpCg4Wz5KP7V
cp0NRmrhbDhYYQ/r5r5QH+8dfP169k421fGHrbpbnoWZ3DnIlwguegk4gtgwiYNf
GCcpHlXnwbC8NNahghjWMIIY0gYKKwYBBAGCNwMDATGCGMIwghi+BgkqhkiG9w0B
BwKgghivMIIYqwIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBUQYLKoZIhvcNAQkQAQSg
ggFABIIBPDCCATgCAQEGCisGAQQBhFkKAwEwMTANBglghkgBZQMEAgEFAAQga741
p4V06BoKspVFDu1DOtmjH9A7fhJLS5qeGwGcxC8CBlty/feamxgTMjAxODA4MjMy
MzQ4NTAuOTQ1WjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAj
BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIHNlcnZpY2WgghQtMIIE8TCCA9mg
AwIBAgITMwAAAL3YjYsNB23F7QAAAAAAvTANBgkqhkiG9w0BAQsFADB8MQswCQYD
VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xODAxMzExOTAwNDFaFw0xODA5MDcx
OTAwNDFaMIHKMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
aGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0
IFRpbWUtU3RhbXAgc2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAM1fZB+FH+pDA5akxf/ulw0u3IlKhoSk0plHDk0J4vmSgqfXAr3SsErQmVw3
TgSxXbY1kStdhpql6mQMGwDyOgZMba8NJgI6Cq4nyHLtcPF7BfqCpluZlpD3uXZO
Q6RaQpWmuBH+9HgSMXj6QeY8yxKNB3N+v+3E9pyBAEJiELe8cOMEUddheZHVsMsk
QZRkKZKzBHV8V6GdgGBhGstcRzzXBEmAIixutgPqV9B3ZZQjhTGNMVpSvYbeJvb4
urTLpF2P1uTUrtq0la8D7tIq140bCdidRLhXecaBR2DkXdFWy0z2OIttCmXltVwv
ZVRuqBYMu0CuC5LRnGyM1JLi83ECAwEAAaOCARswggEXMB0GA1UdDgQWBBSuQ8Ng
UZrU0aCJ+/yT59yRLaHjETAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVt
VTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
L2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYB
BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
cGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8E
AjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQARcJye
SwFc/tYcZ1ybtwx1yLybyHTRgItFM69JEuTWXCV1nI+RtrD6M8DZrAsBZxZEqsBo
0zzJhu7mZv2A96H+bAn4yPQDet19jqL7FKPIaISq6tTMYBNeA3iczr4f0+qh9k8z
SHx7azaS9jeu+lOgE7LJ8ZFSXRmSpdtwkohM5KdCUG2CrMbBVvwbYrJFHZhVPqDw
0uWVBBDl74vBsnZyKRvcA3yR4d6phXLESDZ3Enhpia5IWVATur/lzsElQiWtulMF
681gHu0WoT34xlPp39JcD8ksxlXac9h5SySdfgKZu0XpqL3tXntadhrY/yQCyPPC
6xf37M4QMUhxFhr7MIIF7TCCA9WgAwIBAgIQKMw6Jb+6RKxEmptYa0M5qjANBgkq
hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
IDIwMTAwHhcNMTAwNjIzMjE1NzI0WhcNMzUwNjIzMjIwNDAxWjCBiDELMAkGA1UE
BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC5CJ4o5OTsBk5QaLNBxXvrrraOr4G6IkQfZTRpTL5w
QBfyFnvief2G7Q059BuorZKQHss9do9a2bWREC48BY2KbSRU5x/tVq2DtFCcFaUX
dIhZIPwIxYR202jUbyh4zly481CQRP/jY1++oZoslhUE1gf+HoQh4EIxEcQoNpTP
UKRinsnWq3EAslsM5pbUCiSW9f/G1bcb18u3IWKvEtyhXTfjGvsaRpjAm8DnYx8q
CJMCfh5qjvKfGInkIoWisYRXQP/1DthvnO3iRTEBzRfpf7CBReOqIUAmoXKqp088
AQV+7oNYsV4GY5likXiCtw2TDCRqtBvbJ+xflQQ/k0ow9ZcYs6f5GaeTMx0ByNsi
UlzXJclG+aL7h1lDvptisY0thkQaRqx4YX4wCfquicRBKiJmA5E5RZzHiwyoyg0v
+1LqDPdjMyOd/rAfrWfWp1ADxgRwY7UssYZaQ7f7rvluKW4hIUEmBozJw+6wwoWT
obmF2eYybEtMP9Zdo+W1nXfDnMBVt3QA47g4q4OXUOGaQiQdxsCjMNEaWshSNPdz
8ccYHzOteuzLQWDzI5QgwkhFrFxRxi6AwuJ3Fb2Fh+02nZaR7gC1o3Dsn+ONgGiD
drqvXXBSIhbiZvu6s8XC9z4vd6bK3sGmxkhMwzdRI9Mn17hOcJbwoUR2r3jPmuFm
EwIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU1fZWy4/oolxiaNE9lJBb186aGMQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZI
hvcNAQELBQADggIBAKylloy/u66m9tdxh0MxVoj9HDJxWzW31PCR8q834hTx8wIm
BT4WFH8UurhP+4mysufUCcxtuVs7ZGVwZrfysVrfGgLz9VG4Z215879We+SEuSse
m0CcJjT5RxiYadgc17bRv49hwmfEte9gQ44QGzZJ5CDKrafBsSdlCfjN9Vsq0IQz
8+8f8vWcC1iTN6B1oN5y3mx1KmYi9YwGMFafQLkwqkB3FYLXi+zA07K9g8V3DB6u
rxlToE15cZ8PrzDOZ/nWLMwiQXoH8pdCGM5ZeRBV3m8Q5Ljag2ZAFgloI1uXLiaa
ArtXjMW4umliMoCJnqH9wJJ8eyszGYQqY8UAaGL6n0eNmXpFOqfp7e5pQrXzgZtH
VhB7/HA2hBhz6u/5l02eMyPdJgu6Krc/RNyDJ/+9YVkrEbfKT9vFiwwcMa4y+Pi5
Qvd/3GGadrFaBOERPWZFtxhxvskkhdbz1LpBNF0SLSW5jaYTSG1LsAd9mZMJYYF0
VyaKq2nj5NnHiMwk2OxSJFwevJEU4pbe6wrant1fs1vb1ILsxiBQhyVAOvvH7s3+
M+Vuw4QJVQMlOcDpNV1lMaj2v6AJzSnHszYyLtyV84PBWs+LjfbqsyH4pO0eMQ62
TBGrYAukEiMiF6M2ZIKRBBLgq28ey1AFYbRA/1mGcdHVM2l8qXOKONdkDPFpMIIG
cTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1
WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9p
lGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEw
WbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeG
MoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJ
UGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw
2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0C
AwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ
80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
b20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmww
WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYD
VR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6
Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYI
KwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0
AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9
naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtR
gkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzy
mXlKkVIArzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCf
Mkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3D
nKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs
9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110
mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL
2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffI
rE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxE
PJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc
1bN+NR4Iuto229Nfj950iEkSoYICzjCCAjcCAQEwgfihgdCkgc0wgcoxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
TWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFu
ZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhE
NDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBzZXJ2
aWNloiMKAQEwBwYFKw4DAhoDFQChPoxMmIZuEWMk6cxY3cUodu5pfKCBgzCBgKR+
MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA
3ylZxDAiGA8yMDE4MDgyNDAwMDUyNFoYDzIwMTgwODI1MDAwNTI0WjB3MD0GCisG
AQQBhFkKBAExLzAtMAoCBQDfKVnEAgEAMAoCAQACAh6eAgH/MAcCAQACAhEuMAoC
BQDfKqtEAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAfe4MANX6MVHfhO8F
b34yggT5N/39QUsPk1Nm/Y3yOIeFQEMpdBFLmbdBGt7rCqD5G+w+ex6tVaKoR+d9
ztJMoXIUfaVD0mqv/Y5af/9hKQ9aCXa/eauH/6sg0iVKofIqQv6rHk6blTfKRzlS
UrRvLDseF676y20USpKdorbzOycxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJV
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAL3YjYsNB23F7QAAAAAAvTANBglghkgBZQME
AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
BDEiBCBYBrZlDYDLjVuak1/FwjWhan1iZuUly1htw/aSaGSpeDCB+gYLKoZIhvcN
AQkQAi8xgeowgecwgeQwgb0EIE4Sqp+RZ8AVYpqAorA8z7lQBqm+3b/Yd1fzlmHC
HTF2MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAC9
2I2LDQdtxe0AAAAAAL0wIgQgp339M5a2zXrDB9GQsmZQRFOiarro5Gqrh/7EpMgZ
EKcwDQYJKoZIhvcNAQELBQAEggEANegkRQm1ULY0YyV5YAEgIboN/hrMcIYBq8I8
SbzUkD8/u3FF/rQbJh1bSzp1ywH1yCtl/gDF2SdZXTA6eywjjY4Rq31/RFPopgNk
rb2wyHHUiImpXRW3ELfaIaAUqzMw+wyUfYS8HiR7YST67GZy6p30GFnIBzH6ifEH
mjlibxNVTBEiD4mXwr8qT676M+95xiHxAsJd2YtnG61cXYBsq1SDJxyvsU7FAiau
IdcUs8zdPZBWtfB4TMNxjOtaQs35JewZ611r8/73PKVnVin2aainZxebfCSiDzRy
/r5TdnpNmi9FQItlhOtm4h0WvPlhl1NplpcXSTLHjqzi4m+MEw==
-----END PKCS7-----`
