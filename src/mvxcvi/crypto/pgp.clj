(ns mvxcvi.crypto.pgp
  "Functions for interacting with BouncyCastle's OpenPGP library."
  (:require
    [potemkin :refer [import-vars]]
    (mvxcvi.crypto.pgp
      codec key keyring signature)))


(import-vars
  (mvxcvi.crypto.pgp.key
    public-key
    secret-key
    key-id
    key-algorithm
    unlock-key
    key-info)
  (mvxcvi.crypto.pgp.keyring
    load-public-keyring
    load-secret-keyring)
  (mvxcvi.crypto.pgp.signature
    sign
    verify)
  (mvxcvi.crypto.pgp.codec
    encode
    encode-ascii
    decode
    decode-public-key
    decode-signature))
