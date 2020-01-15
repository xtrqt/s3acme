package structs

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/davecgh/go-spew/spew"
)

type DomainStore struct {
	*Store
}

func (ds DomainStore) GetUser() *MyUser {
	b, err := ds.Get("user.json")
	if err != nil {
		return nil
	}

	var mu MyUser
	spew.Dump(string(b))
	err = json.Unmarshal(b, &mu)
	if err != nil {
		log.Print(err)
		return nil
	}
	return &mu
}

func (ds DomainStore) GetOrRegisterUser(reg func(u *MyUser) *MyUser) (*MyUser, error) {
	u := ds.GetUser()

	mu := reg(u)
	if mu == nil {
		return nil, fmt.Errorf("user is nil")
	}
	spew.Dump(mu, u)
	if u == nil ||
		(u.Registration != nil &&
			mu.Registration != nil &&
			mu.Registration.URI != u.Registration.URI) {

		b, err := json.Marshal(&mu)
		if err != nil {
			return nil, err
		}

		err = ds.Put("user.json", b)
		if err != nil {
			return nil, err
		}
	}

	return mu, nil
}

func (ds DomainStore) GetOrCreateCert(domains []string, isValid func(cert []byte) bool, request func(domains []string) ([]byte, []byte, error)) (key []byte, cert []byte, err error) {
	a := struct {
		Certs []byte
		Key   []byte
	}{}

	if len(domains) < 1 {
		return nil, nil, errors.New("domains parameter is empty")
	}

	name := fmt.Sprintf("%s.pem", domains[0])
	b, err := ds.Get(name)
	if err == nil {
		err = json.Unmarshal(b, &a)
		if err == nil && isValid(a.Certs) {
			return a.Key, a.Certs, nil
		}
	}

	key, cert, err = request(domains)
	if err != nil {
		return nil, nil, err
	}
	a.Key = key
	a.Certs = cert
	b, err = json.Marshal(&a)
	err = ds.Put(name, b)
	if err != nil {
		return nil, nil, err
	}
	return
}

type Store struct {
	*s3.S3
	bucket string
	prefix string
}

func NewStore(endpoint string, id string, secret string, bucket string, prefix string) *Store {
	return &Store{
		S3: s3.New(
			session.Must(
				session.NewSession(
					new(aws.Config).
						WithLogLevel(aws.LogDebug).
						WithCredentials(
							credentials.NewStaticCredentials(
								id,
								secret,
								"")).
						WithEndpoint(endpoint).
						WithRegion("us-west-2"),
				),
			),
		),
		bucket: bucket,
		prefix: prefix,
	}
}

func (s Store) GetPath(k string) string {
	return path.Join(s.prefix, k)
}
func (s Store) Get(name string) ([]byte, error) {
	o, err := s.GetObject(new(s3.GetObjectInput).SetBucket(s.bucket).SetKey(s.GetPath(name)))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(o.Body)
}

func (s Store) Put(name string, data []byte) error {
	_, err := s.PutObject(new(s3.PutObjectInput).SetBucket(s.bucket).SetKey(s.GetPath(name)).SetBody(bytes.NewReader(data)))
	if err != nil {
		return err
	}
	return nil
}

func (s Store) List() ([]string, error) {
	o, err := s.ListObjects(new(s3.ListObjectsInput).SetBucket(s.bucket).SetPrefix(s.prefix))
	if err != nil {
		return nil, err
	}

	out := make([]string, len(o.Contents))
	for i, obj := range o.Contents {
		out[i] = *obj.Key
	}
	return out, nil
}

func NeedRenewal(x509Cert *x509.Certificate, domain string, days int) bool {
	if x509Cert.IsCA {
		log.Fatalf("[%s] Certificate bundle starts with a CA certificate", domain)
	}

	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			log.Printf("[%s] The certificate expires in %d days, the number of days defined to perform the renewal is %d: no renewal.",
				domain, notAfter, days)
			return false
		}
	}

	return true
}
