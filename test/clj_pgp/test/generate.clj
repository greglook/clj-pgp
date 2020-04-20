(ns clj-pgp.test.generate
  (:require
    [clj-pgp.core :as pgp]
    [clj-pgp.generate :as pgp-gen]
    [clj-pgp.keyring :as keyring]
    [clojure.test :refer [deftest is]])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPSecretKeyRing)))


(deftest keyring-macro-generation
  (is (thrown? clojure.lang.Compiler$CompilerException
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd")))
      "A master-key spec is required.")

  (is (thrown? clojure.lang.Compiler$CompilerException
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd"
                 (master-key (keypair rsa :rsa-general))
                 (master-key (keypair rsa :rsa-general)))))
      "Multiple master-key specs are illegal.")

  (is (thrown? clojure.lang.Compiler$CompilerException
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd"
                 (master-key (keypair rsa :rsa-general))
                 ..some-val..)))
      "Malformed subkey specs are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd"
                 (master-key ..keypair-1..)
                 (foobar-key ..keypair-2..))))
      "Unknown subkey spec types are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd"
                 (master-key
                   '..keypair-1..
                   ..some-val..))))
      "Malformed signature subpackets are illegal.")

  (is (thrown? Exception
        (eval '(clj-pgp.generate/generate-keys
                 "user" "p4ssw0rd"
                 (master-key
                   '..keypair-1..
                   (foobar-option ..arg..)))))
      "Unknown signature subpacket types are illegal."))


(deftest keyring-generation
  (let [rsa (pgp-gen/rsa-keypair-generator 1024)
        keyrings (pgp-gen/generate-keys
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
    (let [[mk sk ek] (keyring/list-secret-keys (:secret keyrings))
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
