(ns mvxcvi.crypto.pgp.test.key-utils
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    (mvxcvi.crypto.pgp
      [generate :as pgp-gen]
      [tags :as tags])
    [mvxcvi.crypto.pgp.test.keys :as test-keys
     :refer [privkey pubkey pubring seckey secring]])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)))


(deftest keyrings
  (testing "public keyring contains two public keys"
    (let [pks (pgp/list-public-keys pubring)]
      (is (= 2 (count pks)))
      (is (instance? PGPPublicKey (nth pks 0)))
      (is (instance? PGPPublicKey (nth pks 1)))))
  (testing "secret keyring contains two public keys"
    (let [pks (pgp/list-public-keys secring)]
      (is (= 2 (count pks)))
      (is (instance? PGPPublicKey (nth pks 0)))
      (is (instance? PGPPublicKey (nth pks 1)))))
  (testing "secret keyring contains two secret keys"
    (let [pks (pgp/list-secret-keys secring)]
      (is (= 2 (count pks)))
      (is (instance? PGPSecretKey (nth pks 0)))
      (is (instance? PGPSecretKey (nth pks 1))))))


(deftest key-id-coercion
  (is (nil? (pgp/key-id nil))
      "nil returns nil")
  (is (= 1234 (pgp/key-id 1234))
      "longs return value")
  (is (= 4557904421870553981
         (pgp/key-id pubkey)
         (pgp/key-id seckey)
         (pgp/key-id privkey))
      "key ids match")
  (testing "hex strings return numeric value"
    (is (= -7909697412827827830 (pgp/key-id "923b1c1c4392318a")))
    (is (=  4557904421870553981 (pgp/key-id "3f40edec41c6cb7d"))))
  (is (thrown? IllegalArgumentException
               (pgp/key-id (Object.)))
      "unknown types return an error"))


(deftest hex-key-id
  (is (nil? (pgp/hex-id nil))
      "nil returns nil")
  (is (= "3f40edec41c6cb7d" (pgp/hex-id 4557904421870553981))
      "longs returns hex"))


(deftest hex-fingerprints
  (is (nil? (pgp/hex-fingerprint nil))
      "nil returns nil")
  (is (= "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
         (pgp/hex-fingerprint seckey))
      "keys return hex strings"))


(deftest key-algorithm-coercion
  (is (nil? (pgp/key-algorithm nil))
      "nil returns nil")
  (is (= :rsa-general (pgp/key-algorithm :rsa-general))
      "keywords return value")
  (is (= :rsa-general
         (pgp/key-algorithm pubkey)
         (pgp/key-algorithm seckey)
         (pgp/key-algorithm privkey))
      "keys return keyword values")
  (is (thrown? IllegalArgumentException
               (pgp/key-algorithm ::invalid-algo))
      "unknown algorithms return an error")
  (is (thrown? IllegalArgumentException
               (pgp/key-algorithm (Object.)))
      "unknown types return an error"))


(deftest public-key-coercion
  (is (nil? (pgp/public-key nil))
      "nil returns nil")
  (is (identical? pubkey (pgp/public-key pubkey))
      "public keys return themselves"))


(deftest private-key-coercion
  (is (nil? (pgp/private-key nil))
      "nil returns nil")
  (is (identical? privkey (pgp/private-key privkey))
      "private keys return themselves"))


(deftest secret-key-unlocking
  (is (instance? PGPPrivateKey privkey)
    "secret keys unlock into private keys")
  (is (thrown? Exception (pgp/unlock-key seckey "wrong password"))
      "unlocking with the wrong password throws an exception"))


(deftest key-info
  (is (nil? (pgp/key-info nil))
      "nil returns nil")
  (let [info (pgp/key-info test-keys/master-pubkey)
        expected
        {:key-id "923b1c1c4392318a"
         :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A"
         :algorithm :rsa-general
         :strength 1024
         :master-key? true
         :encryption-key? true
         :user-ids ["Test User <test@vault.mvxcvi.com>"]}]
    (doseq [[k v] expected]
      (is (= v (get info k)))))
  (let [info (pgp/key-info seckey)
        expected
        {:key-id "3f40edec41c6cb7d"
          :fingerprint "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
          :algorithm :rsa-general
          :strength 1024
          :master-key? false
          :secret-key? true
          :encryption-key? true
          :signing-key? true}]
    (doseq [[k v] expected]
      (is (= v (get info k))))))


(deftest public-key-binary-encoding
  (let [encoded-key (pgp/encode pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (instance? PGPPublicKey decoded-key)
        "key is decoded as a PGP public key")
    (is (bytes= encoded-key (pgp/encode decoded-key))
        "encoded key is canonical")))


(deftest public-key-ascii-encoding
  (let [encoded-key (pgp/encode-ascii pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (string? encoded-key)
        "key is encoded as a string")
    (is (instance? PGPPublicKey decoded-key)
        "key is decoded as a PGP public key")
    (is (= encoded-key (pgp/encode-ascii decoded-key))
        "encoded key is canonical")))



;; ## Macro Expansion

(deftest keyring-macro-generation
  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys ..user-id.. ..passphrase..)))
      "A master-key spec is required.")

  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (master-key ..keypair-2..))))
      "Multiple master-key specs are illegal.")

  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 ..some-val..)))
      "Malformed subkey specs are illegal.")

  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key ..keypair-1..)
                 (foobar-key ..keypair-2..))))
      "Unknown subkey spec types are illegal.")

  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys
          ..user-id.. ..passphrase..
          (master-key
            ..keypair-1..
            ..some-val..))))
      "Malformed signature subpackets are illegal.")

  (is (thrown? Exception
        (eval '(pgp-gen/generate-keys
                 ..user-id.. ..passphrase..
                 (master-key
                   ..keypair-1..
                   (foobar-option ..arg..)))))
      "Unknown signature subpacket types are illegal."))
