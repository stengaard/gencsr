// gencsr generate certificate signing requests.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
)

func keyIfExists(f string) (*rsa.PrivateKey, error) {
	keyFile, err := os.Open(f)
	if err != nil {
		return nil, err
	}

	log.Println(f, "exists - using existing RSA key")

	keyPem, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(keyPem)
	if b == nil {
		return nil, fmt.Errorf("no pem data found in %s", f)
	}
	priv, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func parseSubject(sub string) (pkix.Name, error) {
	n := pkix.Name{}
	for _, elem := range strings.Split(sub, "/") {
		if elem == "" {
			continue
		}
		v := strings.SplitN(elem, "=", 2)
		if len(v) == 1 {
			return n, fmt.Errorf("malformed subject - format is \"/C=$yourcountry/.../\" - you set %s", sub)
		}

		key, val := v[0], v[1]
		switch strings.ToUpper(key) {
		case "C":
			n.Country = append(n.Country, val)
		case "ST":
			n.Province = append(n.Province, val)
		case "L":
			n.Locality = append(n.Locality, val)
		case "O":
			n.Organization = append(n.Organization, val)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, val)
		case "SN":
			n.SerialNumber = val
		case "CN":
			n.CommonName = val
		default:
			return n, fmt.Errorf("unknown key '%s' in subject '%s'", key, sub)
		}
	}

	return n, nil
}

func usage() {
	bin := path.Base(os.Args[0])

	fmt.Fprintf(os.Stderr, "%s generates certificate signing requests for you\n", bin)
	fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", bin)
	fmt.Fprintf(os.Stderr, " %s [opts] <subject> <domain> [<domain> ...]\n\n", bin)
	fmt.Fprint(os.Stderr, "format of subject is '/C=<country code>/...'\n")
	fmt.Fprint(os.Stderr, "the recognized subject fields are:"+
		"\n\t C (country)"+
		"\n\t ST (state)"+
		"\n\t L (locality)"+
		"\n\t O (organization)"+
		"\n\t OU (organizational unit)"+
		"\n\t SN (serial number)"+
		"\n\t CN (common name).\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")

	flag.PrintDefaults()

}

func main() {

	var (
		name = flag.String("name", "-", "File name basis for certificate request. '-' means use stdout.")
	)

	flag.Usage = usage
	flag.Parse()

	log.SetFlags(0)

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	subject := args[0]
	domains := args[1:]
	sub, err := parseSubject(subject)
	if err != nil {
		log.Fatal(err)
	}

	csrOut, keyOut := os.Stdout, os.Stdout
	writeKey := true
	var priv *rsa.PrivateKey
	var keyName, csrName string

	if *name != "-" {
		keyName = *name + "-key.pem"
		csrName = *name + "-csr.pem"
	}

	if keyName != "" {
		priv, err = keyIfExists(keyName)
		if os.IsNotExist(err) {
			keyOut, err = os.Create(keyName)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			keyOut, err = os.Create(os.DevNull)
			if err != nil {
				log.Fatal(err)
			}
		}
		defer keyOut.Close()
	}
	if csrName != "" {
		csrOut, err = os.Create(csrName)
		if err != nil {
			log.Fatal(err)
		}
		defer csrOut.Close()
	}

	if priv == nil {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
	}

	req := &x509.CertificateRequest{
		Subject:  sub,
		DNSNames: domains,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(csrOut, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	if err != nil {
		log.Fatal(err)
	}

	if writeKey {

		asnKey := x509.MarshalPKCS1PrivateKey(priv)
		if err != nil {
			log.Fatal(err)
		}

		err = pem.Encode(keyOut,
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: asnKey,
			})
		if err != nil {
			log.Fatal(err)
		}
	}
}
