(ns clj-pgp
  "Functions for interacting with BouncyCastle's OpenPGP library."
  (:require
    [potemkin :refer [import-vars]]
    (clj-pgp
      codec generate keyring message signature util)))


(import-vars
  (clj-pgp.util
    key-algorithm
    key-id
    hex-id
    hex-fingerprint
    key-info
    public-key
    private-key
    unlock-key)
  (clj-pgp.keyring
    get-public-key
    get-secret-key
    list-public-keys
    list-secret-keys
    load-public-keyring
    load-secret-keyring)
  (clj-pgp.generate
    generate-keys
    generate-keypair
    ec-keypair-generator
    rsa-keypair-generator)
  (clj-pgp.signature
    sign
    verify)
  (clj-pgp.message
    literal-data-stream
    compressed-data-stream
    encrypted-data-stream
    armored-data-stream
    message-output-stream
    build-message
    encrypt
    message-input-stream
    read-message
    decrypt)
  (clj-pgp.codec
    encode
    encode-ascii
    decode
    decode-public-key
    decode-signature))
