(ns mvxcvi.crypto.pgp.test.generate
  (:require
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPSecretKeyRing)))


(deftest keyring-macro-generation
  (is (thrown? IllegalArgumentException
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 ..user-id.. ..passphrase..)))
      "A master-key spec is required.")

  (is (thrown? IllegalArgumentException
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (master-key ..keypair-2..))))
      "Multiple master-key specs are illegal.")

  (is (thrown? IllegalArgumentException
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 ..some-val..)))
      "Malformed subkey specs are illegal.")

  (is (thrown? Exception
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (foobar-key ..keypair-2..))))
      "Unknown subkey spec types are illegal.")

  (is (thrown? Exception
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 '..user-id.. '..passphrase..
                 (master-key
                   '..keypair-1..
                   ..some-val..))))
      "Malformed signature subpackets are illegal.")

  (is (thrown? Exception
        (eval '(mvxcvi.crypto.pgp/generate-keys
                 '..user-id.. '..passphrase..
                 (master-key
                   '..keypair-1..
                   (foobar-option ..arg..)))))
      "Unknown signature subpacket types are illegal."))


(deftest keyring-generation
  (let [rsa (pgp/rsa-keypair-generator 1024)
        keyrings (pgp/generate-keys
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
                     (keypair rsa :rsa-general)))]
    (is (instance? PGPPublicKeyRing (:public keyrings)))
    (is (instance? PGPSecretKeyRing (:secret keyrings)))
    ; TODO: test keys
    ))