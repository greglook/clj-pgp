(ns mvxcvi.crypto.pgp.generate-test
  (:require
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.generate :as pgp-gen])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPSecretKeyRing)))


(facts "Keyring macro generation"
  (fact "A master-key spec is required."
    (eval '(pgp-gen/generate-keys ..user-id.. ..passphrase..))
    => (throws Exception))

  (fact "Multiple master-key specs are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             (master-key ..keypair-2..)))
    => (throws Exception))

  (fact "Malformed subkey specs are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             ..some-val..))
    => (throws Exception))

  (fact "Unknown subkey spec types are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             (foobar-key ..keypair-2..)))
    => (throws Exception))

  (fact "Malformed signature subpackets are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key
               ..keypair-1..
               ..some-val..)))
    => (throws Exception))

  (fact "Unknown signature subpacket types are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key
               ..keypair-1..
               (foobar-option ..arg..))))
    => (throws Exception))

  (fact "Full macro expansion."
    (pgp-gen/generate-keys
      ..user-id.. ..passphrase..
      (master-key
        (keypair ..rsa.. :rsa-sign)
        (prefer-symmetric :aes-256 :aes-192 :aes-128)
        (prefer-hash :sha512 :sha384 :sha256 :sha224 :sha1)
        (prefer-compression :zlib :bzip2 :zip :uncompressed))
      (signing-key
        ..signing-keypair..
        (expires 3600))
      (encryption-key
        (keypair ..rsa.. :rsa-encrypt)))

    =expands-to=>

    (mvxcvi.crypto.pgp.generate/generate-keyrings
      (clojure.core/doto
        (mvxcvi.crypto.pgp.generate/keyring-generator
          ..user-id.. ..passphrase..
          (mvxcvi.crypto.pgp.generate/generate-keypair ..rsa.. :rsa-sign)
          (clojure.core/doto
            (mvxcvi.crypto.pgp.generate/master-signature-generator)
            (mvxcvi.crypto.pgp.generate/prefer-symmetric-algorithms! :aes-256 :aes-192 :aes-128)
            (mvxcvi.crypto.pgp.generate/prefer-hash-algorithms! :sha512 :sha384 :sha256 :sha224 :sha1)
            (mvxcvi.crypto.pgp.generate/prefer-compression-algorithms! :zlib :bzip2 :zip :uncompressed)))
        (mvxcvi.crypto.pgp.generate/add-subkey!
          ..signing-keypair..
          (clojure.core/doto
            (mvxcvi.crypto.pgp.generate/signing-subkey-signature-generator)
            (mvxcvi.crypto.pgp.generate/set-key-expiration! 3600)))
        (mvxcvi.crypto.pgp.generate/add-subkey!
          (mvxcvi.crypto.pgp.generate/generate-keypair ..rsa.. :rsa-encrypt)
          (mvxcvi.crypto.pgp.generate/encryption-subkey-signature-generator))))))


(facts "RSA key generation"
  (let [rsa (pgp-gen/rsa-keypair-generator 1024)
        keyrings
        (pgp-gen/generate-keys
          "Test User <test@mvxcvi.com>" "test password"
          (master-key
            (keypair rsa :rsa-sign)
            (prefer-symmetric :aes-256 :aes-192 :aes-128)
            (prefer-hash :sha256 :sha1)
            (prefer-compression :zip :uncompressed))
          (signing-key
            (keypair rsa :rsa-sign)
            (expires 3600))
          (encryption-key
            (keypair rsa :rsa-encrypt)))]
    keyrings => (contains {:public (partial instance? PGPPublicKeyRing)
                           :secret (partial instance? PGPSecretKeyRing)})
    ; TODO: more tests
    ))
