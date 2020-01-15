package structs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"log"

	"github.com/go-acme/lego/v3/registration"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          *ecdsa.PrivateKey
}

func (u *MyUser) UnmarshalJSON(b []byte) error {
	var a = struct {
		Email        *string
		Registration *registration.Resource
		Key          []byte
	}{&u.Email, nil, []byte{}}
	err := json.Unmarshal(b, &a)
	if err != nil {
		return err
	}

	u.Key, err = x509.ParseECPrivateKey(a.Key)
	if err != nil {
		return err
	}
	u.Registration = a.Registration
	return nil

}

func (u *MyUser) MarshalJSON() ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(u.Key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Email        string
		Registration interface{}
		Key          []byte
	}{
		u.Email,
		u.Registration,
		b,
	})
}

func NewUser(email string) *MyUser {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return &MyUser{
		Email:        email,
		Registration: nil,
		Key:          privateKey, // Create a user. New accounts need an email and private key to start.
	}
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return crypto.PrivateKey(u.Key)
}
