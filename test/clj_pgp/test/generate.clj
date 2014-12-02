(ns clj-pgp.test.generate
  (:require
    [clojure.test :refer :all]
    [clj-pgp :as pgp])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPSecretKeyRing)))


(deftest keyring-macro-generation
  (is (thrown? IllegalArgumentException
        (eval '(clj-pgp/generate-keys
                 ..user-id.. ..passphrase..)))
      "A master-key spec is required.")

  (is (thrown? IllegalArgumentException
        (eval '(clj-pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (master-key ..keypair-2..))))
      "Multiple master-key specs are illegal.")

  (is (thrown? IllegalArgumentException
        (eval '(clj-pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 ..some-val..)))
      "Malformed subkey specs are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (foobar-key ..keypair-2..))))
      "Unknown subkey spec types are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp/generate-keys
                 '..user-id.. '..passphrase..
                 (master-key
                   '..keypair-1..
                   ..some-val..))))
      "Malformed signature subpackets are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp/generate-keys
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
    (let [[mk sk ek] (pgp/list-secret-keys (:secret keyrings))
          mk-info (pgp/key-info mk)
          sk-info (pgp/key-info sk)
          ek-info (pgp/key-info ek)]
      (is (:master-key? mk-info))
      (is (not (:master-key? sk-info)))
      (is (not (:master-key? ek-info)))
      (is (= :rsa-general
             (:algorithm mk-info)
             (:algorithm sk-info)
             (:algorithm ek-info)))
      (is (:encryption-key? ek-info))
      (is (:signing-key? sk-info))
      (is (:expires-at sk-info)))))
