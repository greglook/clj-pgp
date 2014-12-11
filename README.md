clj-pgp
=======

[![Build Status](https://travis-ci.org/greglook/clj-pgp.svg?branch=master)](https://travis-ci.org/greglook/clj-pgp)
[![Coverage Status](https://coveralls.io/repos/greglook/clj-pgp/badge.png?branch=master)](https://coveralls.io/r/greglook/clj-pgp?branch=master)
[![Dependency Status](https://www.versioneye.com/user/projects/53718e2314c1589a89000149/badge.png)](https://www.versioneye.com/clojure/mvxcvi:clj-pgp/0.8.0)
**master**
<br/>
[![Build Status](https://travis-ci.org/greglook/clj-pgp.svg?branch=develop)](https://travis-ci.org/greglook/clj-pgp)
[![Coverage Status](https://coveralls.io/repos/greglook/clj-pgp/badge.png?branch=develop)](https://coveralls.io/r/greglook/clj-pgp?branch=develop)
[![Dependency Status](https://www.versioneye.com/user/projects/53718e1914c1581079000056/badge.png)](https://www.versioneye.com/clojure/mvxcvi:clj-pgp/0.9.0-SNAPSHOT)
**develop**

This is a Clojure library which wraps the Bouncy Castle OpenPGP implementation.
API documentation can be found [here](https://greglook.github.io/clj-pgp/api/),
along with a [literate view](https://greglook.github.io/clj-pgp/marginalia/toc.html)
of the code.

## Usage

Library releases are published on Clojars. To use the latest version with
Leiningen, add the following dependency to your project definition:

[![Clojars Project](http://clojars.org/mvxcvi/clj-pgp/latest-version.svg)](http://clojars.org/mvxcvi/clj-pgp)

The main interface to the library is the `clj-pgp.core` namespace, which
provides many general functions for working with PGP keys and data.

***NOTE:*** 0.8.0 is a breaking API change! The namespaces changed from
`mvxcvi.crypto.pgp.foo` to `clj-pgp.foo`, among many other functionality
improvements.

### PGP Keys

PGP stores keys in _keyrings_, which are collections of related asymmetric keys.
Public keyrings store just the public key from each keypair, and may store keys
for other people as well as keys controlled by the user. Secret keyrings store
both the public and private parts of a keypair, encrypted with a secret
passphrase.

```clojure
(require
  '[clojure.java.io :as io]
  '(clj-pgp
     [core :as pgp]
     [keyring :as keyring]))

(def keyring
  (keyring/load-secret-keyring (io/file "~/.gpg/secring.gpg")))

(keyring/list-public-keys keyring)
=> (#<PGPPublicKey ...> #<PGPPublicKey ...>)

(def pubkey (first *1))

(pgp/key-id pubkey)
=> -7909697412827827830

(pgp/hex-id pubkey)
=> "923b1c1c4392318a"

(def seckey (keyring/get-secret-key keyring *1))

(pgp/key-algorithm seckey)
=> :rsa-general

(pgp/key-info pubkey)
=> {:master-key? true,
    :key-id "923b1c1c4392318a",
    :strength 1024,
    :algorithm :rsa-general,
    :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A",
    :encryption-key? true,
    :user-ids ["Test User <test@mvxcvi.com>"]}
```

Keypairs and keyrings can be created using the `clj-pgp.generate` namespace.
RSA and EC keys can be generated directly or as part of a keyring, which binds a
master key together with signing and encryption subkeys. The `generate-keys`
macro provides a handy syntax for creating new keyrings:

```clojure
(require '[clj-pgp.generate :as pgp-gen])

(def rsa (pgp-gen/rsa-keypair-generator 2048))
(def ec (pgp-gen/ec-keypair-generator "secp160r2"))

(pgp-gen/generate-keypair ec :ecdsa)
=> #<PGPKeyPair ...>

(pgp-gen/generate-keys
  "test user" "test passphrase"
  (master-key
    (keypair rsa :rsa-general)
    (prefer-symmetric :aes-256 :aes-128)
    (prefer-hash :sha512 :sha256 :sha1)
    (prefer-compression :zlib :bzip2))
  (signing-key
    (keypair rsa :rsa-general)
    (expires 36000))
  (encryption-key
    (keypair ec :ecdh)))
=> {:public #<PGPPublicKeyRing ...>
    :secret #<PGPSecretKeyRing ...>}
```

### Message Handling

Data encryption is supported using PGP message packets. The content is encrypted
using a symmetric key algorithm, then the key is encrypted using the given
public key(s) or passphrase. Any matching private key or passphrase can then
decipher and read the message.

Data may also be compressed before encrypting it, and converted to an ASCII
representation after. The ASCII format is sometimes referred to as an "armored"
encoding because it is intended to be transmissible through email.

```clojure
(require '[clj-pgp.message :as pgp-msg])

(def content "my sensitive data")

(def message
  (pgp-msg/encrypt
    content pubkey
    :format :utf8
    :cipher :aes-256
    :compress :zip
    :armor true))

(println message)
;; -----BEGIN PGP MESSAGE-----
;; Version: BCPG v1.49
;;
;; hIwDkjscHEOSMYoBBADGcRtjKmBSAh6L2fVe/1BCZtEbME4zp6GqilETzOYyi5HL
;; Vee++PI03KluhW32i359ycvOre92yHaApcDBRXGwdYBT/hx8ryXov3I1wvZMS/iK
;; Iex91VxkquJnvZvi6/qy3f6WFgLBHT2GCKy+Um4YU2OstykHZP7Gsbr5MZ04K8ks
;; 71TaictIOx2qukbpwnIVNzOl5GeaPy5FiVbntl0Wc3lESD2A9l2pDENyicg=
;; =cvks
;; -----END PGP MESSAGE-----

(def privkey (pgp/unlock-key seckey "test password"))

(println (pgp/decrypt message privkey))
;; my sensitive data

; Or, for more detail:
(pgp-msg/read-messages message :decryptor privkey)
=>
({:data "my sensitive data"
  :cipher :aes-256
  :encrypted-for -7909697412827827830
  :integrity-protected? true
  :compress :zip
  :format :utf8
  :filename "_CONSOLE"
  :mtime #inst "2014-12-06T22:44:59.000-00:00"})
```

### Signatures

PGP keys can be used to sign data by hashing it and encrypting the hash with the
_private_ key. Later, the signature can be verified by decrypting it with the
public key and comparing it with the hash of the data.

```clojure
(require '[clj-pgp.signature :as pgp-sig])

(def sig (pgp-sig/sign content privkey))

(= (pgp/key-id sig) (pgp/key-id privkey))
=> true

(pgp-sig/verify content sig pubkey)
=> true
```

### Serialization

The library provides functions for encoding some PGP objects in both binary and
ASCII formats.

```clojure
(pgp/encode sig)
=> #<byte[] [B@51e4232>

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
=> true
```

## License

This is free and unencumbered software released into the public domain.
See the UNLICENSE file for more information.
