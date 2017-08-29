## x509big

This package provides a partial fork of x509 with support for large integers in the exponent of RSA Public Keys.

This is useful for experimentation with unsual or known faulty RSA keys with public exponents larger than MaxUint64.

## Features

`func ParseBigPKIXPublicKey(derBytes []byte) (pub interface{}, err error)`

returns an interface you can assert to be a `BigPublicKey` type which is defined as

```
type BigPublicKey struct {
  N *big.Int
  E *big.Int
}
```

An example implementation:

```
func parsePublicRsaKey(keyBytes []byte) (*BigPublicKey, error) {
  key, err := x509big.ParseBigPKIXPublicKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }

  switch key := key.(type) {
    case *BigPublicKey:
      fmt.Printf("n = %d\ne = %d\n", key.N, key.E)
      return k, nil
    default:
      return nil, errors.New("Given key is not an RSA Key")
  }
}
```
## Install

Use go to install the library
`go get github.com/ncw/gmp`

## License

As this contains a great deal of code copied from the Go source it is licenced identically to the Go source itself - see the LICENSE file for details.

## Authors

* [The Go team](http://golang.org/AUTHORS)
* Kris Hunt
