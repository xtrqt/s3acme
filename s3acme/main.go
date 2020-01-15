package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtrqt/s3acme/structs"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/providers/dns/digitalocean"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
)

func mustEnv(k string) string {
	return mustEnvD(k, "")
}

func mustEnvD(k string, def string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	if def != "" {
		return def
	}
	log.Fatalf("variable '%s' is empty", k)
	return ""
}

func main() {

	email := mustEnv("S3A_EMAIL")

	var domains = strings.Split(mustEnv("S3A_DOMAINS"), ",")

	store := structs.NewStore(
		mustEnv("S3A_ENDPOINT"),
		mustEnv("S3A_ID"),
		mustEnv("S3A_SECRET"),
		mustEnv("S3A_BUCKET"),
		mustEnv("S3A_PREFIX"))

	outKey, _ := filepath.Abs(mustEnv("S3A_DESTKEYFILE"))
	outCerts, _ := filepath.Abs(mustEnv("S3A_DESTCERTFILE"))
	log.Println("out:", outKey, outCerts)

	doAuth := mustEnv("S3A_DOAUTH")

	ds := structs.DomainStore{Store: store}

	key, certs, err := ds.GetOrCreateCert(domains, func(cert []byte) bool {
		bundle, err := certcrypto.ParsePEMBundle(cert)
		if err != nil {
			return false
		}

		return !structs.NeedRenewal(bundle[0], domains[0], 15)
	}, func(domains []string) (key []byte, cert []byte, err error) {
		var client *lego.Client
		_, err = ds.GetOrRegisterUser(func(u *structs.MyUser) *structs.MyUser {
			var err error
			if u != nil {
				client, err = getClient(u, doAuth)
				if err != nil {
					log.Fatal(err)
				}
				return u
			}
			mu := structs.NewUser(email)
			client, err = getClient(mu, doAuth)
			if err != nil {
				log.Fatal("b", err)
			}
			reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				log.Fatal("a", err)
			}
			mu.Registration = reg
			return mu
		})
		if err != nil {
			log.Fatal(err)
		}

		request := certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		}
		certificates, err := client.Certificate.Obtain(request)
		if err != nil {
			log.Fatal(err)
		}

		// Each certificate comes back with the cert bytes, the bytes of the client's
		// private key, and a certificate URL. SAVE THESE TO DISK.
		fmt.Printf("%#v\n", certificates)
		fmt.Printf("%s\n%s", certificates.PrivateKey, certificates.Certificate)
		return certificates.PrivateKey, certificates.Certificate, nil
	})
	if err != nil {
		log.Fatalf("Problem: %v", err)
	}
	err = ioutil.WriteFile(outCerts, certs, 0600)
	if err != nil {
		log.Printf("Problem: %v ", err)
	}
	err = ioutil.WriteFile(outKey, key, 0600)
	if err != nil {
		log.Printf("Problem: %v ", err)
	}
}

func getClient(myUser *structs.MyUser, doAuth string) (*lego.Client, error) {
	config := lego.NewConfig(myUser)

	if mustEnvD("S3A_STAGING", "0") != "0" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	dc := digitalocean.NewDefaultConfig()
	dc.AuthToken = doAuth
	dp, err := digitalocean.NewDNSProviderConfig(dc)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Challenge.SetDNS01Provider(dp)
	if err != nil {
		log.Fatal(err)
	}
	return client, err
}
