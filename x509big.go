package x509big

import (
  "bytes"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/asn1"
  "errors"
  "math/big"
)

type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// an big public key type
type BigPublicKey struct {
  N *big.Int
  E *big.Int
}

// ParseBigPKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
// Taken from the standard library so we can return a gmp PublicKey
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

// Taken from standard library, removed DSA, ECDSA support and added big.Int exponent support
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