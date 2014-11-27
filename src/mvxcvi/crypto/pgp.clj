(ns mvxcvi.crypto.pgp
  "Functions for interacting with BouncyCastle's OpenPGP library."
  (:require
    [potemkin :refer [import-vars]]
    (mvxcvi.crypto.pgp
      codec data generate keyring signature util)))


(import-vars
  (mvxcvi.crypto.pgp.util
    key-algorithm
    key-id
    hex-id
    hex-fingerprint
    key-info
    public-key
    private-key
    unlock-key)
  (mvxcvi.crypto.pgp.keyring
    list-public-keys
    list-secret-keys
    get-public-key
    get-secret-key
    load-public-keyring
    load-secret-keyring)
  (mvxcvi.crypto.pgp.generate
    generate-keys
    generate-keypair
    ec-keypair-generator
    rsa-keypair-generator)
  (mvxcvi.crypto.pgp.data
    armored-data-stream
    compressed-data-stream
    decrypt
    encrypt
    encrypted-data-stream
    literal-data-stream
    message-packet
    message-stream
    read-message
    read-stream)
  (mvxcvi.crypto.pgp.signature
    sign
    verify)
  (mvxcvi.crypto.pgp.codec
    encode
    encode-ascii
    decode
    decode-public-key
    decode-signature))
