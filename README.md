## x509big

This package provides a partial fork of x509 with support for large integers in the public exponent of RSA Public Keys. It also provides the necessary support to marshal a Private Key with a large public exponent into a PKCS1 Private Key for encoding as ASN1

This is useful for experimentation with unsual or known faulty RSA keys with public exponents larger than MaxUint64.

## Features

 * `func ParseBigPKCS1PublicKey(derBytes []byte) (*BigPublicKey, err error)`
   returns a `*BigPublicKey` type which is defined below.

 * `func ParseBigPKIXPublicKey(derBytes []byte) (*BigPublicKey, err error)`
   returns a `*BigPublicKey` type which is defined below.

 * `func ParseBigPKCS1PrivateKey(der []byte) (*BigPrivateKey, error)`
   returns a `*BigPrivateKey` type which is defined below.

 * `func MarshalPKCS1BigPrivateKey(key *BigPrivateKey) []byte`
   returns a array of bytes suitable to encode with something like `pem.EncodeToMemory()`

 * `func MarshalPKCS1BigPublicKey(key *BigPublicKey) []byte`
   returns a array of bytes suitable to encode with something like `pem.EncodeToMemory()`

## Types
```
type BigPublicKey struct {
  N *big.Int
  E *big.Int
}
```

```
type BigPrivateKey struct {
        PublicKey BigPublicKey  // public part.
        D         *big.Int      // private exponent
        Primes    []*big.Int    // prime factors of N, has >= 2 elements.

        // Precomputed contains precomputed values that speed up private
        // operations, if available.
        Precomputed PrecomputedValues
}
```

## Examples

An example implementation of parsing a RSA Public Key with a large public exponent

```
func parsePublicRsaKey(keyBytes []byte) (*x509big.BigPublicKey, error) {
  key, err := x509big.ParseBigPKCS1PublicKey(keyBytes)
  if err != nil {
    return nil, fmt.Errorf("parsePublicRsaKey: failed to parse the DER key after decoding: %v", err)
  }

  return key, nil
}
```

An example of marshalling a BigPrivateKey type into an PEM private key.

```
func encodeDerToPem(der []byte, t string) string {
  p := pem.EncodeToMemory(
    &pem.Block{
      Type: t, 
      Bytes: der,
      },
    )
  return string(p)
}

func EncodeBigPrivateKey(priv *x509big.BigPrivateKey) string {
  privder := x509big.MarshalPKCS1BigPrivateKey(priv)
  fmt.Println(encodeDerToPem(privder, "RSA PRIVATE KEY"))
}
```

## Install

Use go to install the library
`go get github.com/sourcekris/x509big`

## License

As this contains a great deal of code copied from the Go source it is licenced identically to the Go source itself - see the LICENSE file for details.

## Authors

* [The Go team](http://golang.org/AUTHORS)
* Kris Hunt
