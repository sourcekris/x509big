// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509big

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// BigPublicKey is  big.Int public key type
type BigPublicKey struct {
	N *big.Int
	E *big.Int
}

// BigPrivateKey is a big private key type
type BigPrivateKey struct {
	PublicKey BigPublicKey // public part.
	D         *big.Int     // private exponent
	Primes    []*big.Int   // prime factors of N, has >= 2 elements.

	// Precomputed contains precomputed values that speed up private
	// operations, if available.
	Precomputed PrecomputedValues
}

// PrecomputedValues is directly taken from standard library rsa.PrecomputedValues
// using big.Int types.
type PrecomputedValues struct {
	Dp, Dq *big.Int // D mod (P-1) (or mod Q-1)
	Qinv   *big.Int // Q^-1 mod P

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS#1 and interoperability is sufficiently
	// important that we mirror this.
	CRTValues []CRTValue
}

// CRTValue contains the precomputed Chinese remainder theorem values.
// directly taken from standard library rsa.CRTValues
type CRTValue struct {
	Exp   *big.Int // D mod (prime-1).
	Coeff *big.Int // R·Coeff ≡ 1 mod Prime.
	R     *big.Int // product of primes prior to this (inc p and q).
}

type pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}

// pkcs1BigPrivateKey is a structure which mirrors the PKCS#1 ASN.1 for a RSA private key.
type pkcs1BigPrivateKey struct {
	Version int
	N       *big.Int
	E       *big.Int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	// We ignore these values, if present, because rsa will calculate them.
	Dp   *big.Int `asn1:"optional"`
	Dq   *big.Int `asn1:"optional"`
	Qinv *big.Int `asn1:"optional"`

	AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

// pkcs1BigPublicKey is a structure which mirrors the PKCS#1 ASN.1 for a RSA public key.
type pkcs1BigPublicKey struct {
	N *big.Int
	E *big.Int
}

// ParseBigPKCS1PublicKey parses an RSA public key in PKCS#1, ASN.1 DER form.
func ParseBigPKCS1PublicKey(der []byte) (*BigPublicKey, error) {
	var pub pkcs1BigPublicKey
	rest, err := asn1.Unmarshal(der, &pub)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	if pub.N.Sign() <= 0 || pub.E.Cmp(bigZero) <= 0 {
		return nil, errors.New("x509big: public key contains zero or negative value")
	}

	return &BigPublicKey{
		E: pub.E,
		N: pub.N,
	}, nil
}

// ParseBigPKCS1PrivateKey returns an RSA private key from its ASN.1 PKCS#1 DER encoded form.
func ParseBigPKCS1PrivateKey(der []byte) (*BigPrivateKey, error) {
	var priv pkcs1BigPrivateKey
	rest, err := asn1.Unmarshal(der, &priv)
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	if err != nil {
		return nil, err
	}

	if priv.Version > 1 {
		return nil, errors.New("x509big: unsupported private key version")
	}

	if priv.N.Sign() <= 0 || priv.D.Sign() <= 0 || priv.P.Sign() <= 0 || priv.Q.Sign() <= 0 {
		return nil, errors.New("x509big: private key contains zero or negative value")
	}

	key := new(BigPrivateKey)
	key.PublicKey = BigPublicKey{
		E: priv.E,
		N: priv.N,
	}

	key.D = priv.D
	key.Primes = make([]*big.Int, 2+len(priv.AdditionalPrimes))
	key.Primes[0] = priv.P
	key.Primes[1] = priv.Q
	for i, a := range priv.AdditionalPrimes {
		if a.Prime.Sign() <= 0 {
			return nil, errors.New("x509big: private key contains zero or negative prime")
		}
		key.Primes[i+2] = a.Prime
		// We ignore the other two values because rsa will calculate
		// them as needed.
	}

	key.precompute()

	return key, nil
}

// MarshalPKCS1BigPrivateKey converts a big private key to ASN.1 DER encoded form.
// Taken from the standard library
func MarshalPKCS1BigPrivateKey(key *BigPrivateKey) []byte {
	key.precompute()

	version := 0
	if len(key.Primes) > 2 {
		version = 1
	}

	priv := pkcs1BigPrivateKey{
		Version: version,
		N:       key.PublicKey.N,
		E:       key.PublicKey.E,
		D:       key.D,
		P:       key.Primes[0],
		Q:       key.Primes[1],
		Dp:      key.Precomputed.Dp,
		Dq:      key.Precomputed.Dq,
		Qinv:    key.Precomputed.Qinv,
	}

	priv.AdditionalPrimes = make([]pkcs1AdditionalRSAPrime, len(key.Precomputed.CRTValues))
	for i, values := range key.Precomputed.CRTValues {
		priv.AdditionalPrimes[i].Prime = key.Primes[2+i]
		priv.AdditionalPrimes[i].Exp = values.Exp
		priv.AdditionalPrimes[i].Coeff = values.Coeff
	}

	b, _ := asn1.Marshal(priv)
	return b
}

// MarshalPKCS1BigPublicKey converts a big public key to ASN.1 DER encoded form.
func MarshalPKCS1BigPublicKey(key *BigPublicKey) []byte {
	derBytes, _ := asn1.Marshal(pkcs1BigPublicKey{
		N: key.N,
		E: key.E,
	})
	return derBytes
}

// Precompute performs some calculations that speed up private key operations
// in the future. Taken from the standard library rsa.Precompute
func (priv *BigPrivateKey) precompute() {
	if priv.Precomputed.Dp != nil {
		return
	}

	priv.Precomputed.Dp = new(big.Int).Sub(priv.Primes[0], bigOne)
	priv.Precomputed.Dp.Mod(priv.D, priv.Precomputed.Dp)

	priv.Precomputed.Dq = new(big.Int).Sub(priv.Primes[1], bigOne)
	priv.Precomputed.Dq.Mod(priv.D, priv.Precomputed.Dq)

	priv.Precomputed.Qinv = new(big.Int).ModInverse(priv.Primes[1], priv.Primes[0])

	r := new(big.Int).Mul(priv.Primes[0], priv.Primes[1])
	priv.Precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
	for i := 2; i < len(priv.Primes); i++ {
		prime := priv.Primes[i]
		values := &priv.Precomputed.CRTValues[i-2]

		values.Exp = new(big.Int).Sub(prime, bigOne)
		values.Exp.Mod(priv.D, values.Exp)

		values.R = new(big.Int).Set(r)
		values.Coeff = new(big.Int).ModInverse(r, prime)

		r.Mul(r, prime)
	}
}
