// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509big

import (
  "bytes"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/asn1"
  "errors"
  "math/big"
)

var bigOne = big.NewInt(1)

type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// A big.Int public key type
type BigPublicKey struct {
  N *big.Int
  E *big.Int
}

// a big private key type
type BigPrivateKey struct {
        PublicKey BigPublicKey  // public part.
        D         *big.Int      // private exponent
        Primes    []*big.Int    // prime factors of N, has >= 2 elements.

        // Precomputed contains precomputed values that speed up private
        // operations, if available.
        Precomputed PrecomputedValues
}

// directly taken from standard library rsa.PrecomputedValues
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

// ParseBigPKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
// Taken from the standard library so we can return a BigPublicKey
func ParseBigPKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
  var pki publicKeyInfo
  if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
    return nil, err
  } else if len(rest) != 0 {
    return nil, errors.New("x509big: trailing data after ASN.1 of public-key")
  }
  algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
  if algo == x509.UnknownPublicKeyAlgorithm {
    return nil, errors.New("x509big: unknown public key algorithm")
  }
  return parsePublicKey(algo, &pki)
}

// Taken from standard library
var (
  oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
  oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
  oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Taken from standard library
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
  switch {
  case oid.Equal(oidPublicKeyRSA):
    return x509.RSA
  case oid.Equal(oidPublicKeyDSA):
    return x509.DSA
  case oid.Equal(oidPublicKeyECDSA):
    return x509.ECDSA
  }
  return x509.UnknownPublicKeyAlgorithm
}

// Taken from standard library, removed DSA, ECDSA support and added BigPublicKey support
func parsePublicKey(algo x509.PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
  asn1Data := keyData.PublicKey.RightAlign()
  switch algo {
  case x509.RSA:
    // RSA public keys must have a NULL in the parameters
    // (https://tools.ietf.org/html/rfc3279#section-2.3.1).
    if !bytes.Equal(keyData.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
      return nil, errors.New("x509big: RSA key missing NULL parameters")
    }

    p := new(BigPublicKey)
    rest, err := asn1.Unmarshal(asn1Data, p)
    if err != nil {
      return nil, err
    }
    if len(rest) != 0 {
      return nil, errors.New("x509big: trailing data after RSA public key")
    }

    if p.N.Sign() <= 0 {
      return nil, errors.New("x509big: RSA modulus is not a positive number")
    }
    if p.E.Sign() <= 0 {
      return nil, errors.New("x509big: RSA public exponent is not a positive number")
    }

    pub := &BigPublicKey{
      E: p.E,
      N: p.N,
    }

    return pub, nil
  case x509.DSA:
    return nil,errors.New("x509big: DSA Public Keys not supported")
  case x509.ECDSA:
    return nil,errors.New("x509big: ECDSA Public Keys not supported")
  default:
    return nil, nil
  }
}

// MarshalPKCS1PrivateKey converts a big private key to ASN.1 DER encoded form.
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
