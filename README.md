mvxcvi/clj-pgp
==============

[![Build Status](https://travis-ci.org/greglook/clj-pgp.svg?branch=develop)](https://travis-ci.org/greglook/clj-pgp)

This is a clojure wrapper for the Bouncy Castle OpenPGP library.

## Usage

The library is available as [mvxcvi/clj-pgp](https://clojars.org/mvxcvi/clj-pgp)
on Clojars. To use this version with Leiningen, add the following dependency to
your project definition:

```clojure
[mvxcvi/clj-pgp "0.4.0"]
```

The main interface to the library is the `mvxcvi.crypto.pgp` namespace.

### Keys

The library contains many functions for working with and inspecting PGP keys.

```clojure
(require
  '[clojure.java.io :as io]
  '[mvxcvi.crypto.pgp :as pgp])

(def keyring
  (-> "mvxcvi/crypto/pgp/test-keys/secring.gpg"
      io/resource
      io/file
      pgp/load-secret-keyring))

(pgp/list-public-keys keyring)
; => (#<PGPPublicKey {...}> #<PGPPublicKey {...}>)

(def pubkey (first *1))

(pgp/key-id pubkey)
; => -7909697412827827830

(def seckey (pgp/get-secret-key keyring *1))

(pgp/key-algorithm seckey)
; => :rsa-general

(= (pgp/key-info pubkey)
   {:master-key? true,
    :key-id "923b1c1c4392318a",
    :strength 1024,
    :algorithm :rsa-general,
    :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A",
    :encryption-key? true,
    :user-ids ["Test User <test@vault.mvxcvi.com>"]})
; => true
```

### Signatures

The library also provides support for signature generation and verification.

```clojure
(def privkey (pgp/unlock-key seckey "test password"))
(def content (.getBytes "non-repudiable data"))
(def sig (pgp/sign content :sha1 privkey))

(= (pgp/key-id sig) (pgp/key-id privkey))
; => true

(pgp/verify content sig pubkey)
; => true
```

### Serialization

The library provides functions for encoding in both binary and ASCII formats.

```clojure
(pgp/encode sig)
; => #<byte[] [B@51e4232>

(print (pgp/encode-ascii pubkey))
;; -----BEGIN PGP PUBLIC KEY BLOCK-----
;; Version: BCPG v1.49
;;
;; mI0EUr3KFwEEANAfzcKxWqBYhkUGo4xi6d2zZy2RAewFRKVp/BA2bEHLAquDnpn7
;; abgrpsCFbBW/LEwiMX6cfYLMxvGzbg5oTfQHMs27OsnKCqFas9UkT6DYS1PM9u4C
;; 3qlJytK9AFQnSYOrSs8pe6VRdeHZb7FM+PawqH0cuoYfcMZiGAylddXhABEBAAE=
;; =Hnjf
;; -----END PGP PUBLIC KEY BLOCK-----

(let [ascii (pgp/encode-ascii pubkey)]
  (= ascii (pgp/encode-ascii (pgp/decode-public-key ascii))))
; => true
```

## License

This is free and unencumbered software released into the public domain.
See the UNLICENSE file for more information.
