(ns clj-pgp.test.key-utils
  (:require
    [byte-streams :refer [bytes=]]
    [clj-pgp.core :as pgp]
    [clj-pgp.keyring :as keyring]
    [clj-pgp.test.keys :as test-keys
     :refer [privkey pubkey pubring seckey secring]]
    [clojure.test :refer [deftest testing is]])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)))


(deftest keyrings
  (testing "public keyring contains two public keys"
    (let [pks (keyring/list-public-keys pubring)]
      (is (= 2 (count pks)))
      (is (instance? PGPPublicKey (nth pks 0)))
      (is (instance? PGPPublicKey (nth pks 1)))))
  (testing "secret keyring contains two public keys"
    (let [pks (keyring/list-public-keys secring)]
      (is (= 2 (count pks)))
      (is (instance? PGPPublicKey (nth pks 0)))
      (is (instance? PGPPublicKey (nth pks 1)))))
  (testing "secret keyring contains two secret keys"
    (let [pks (keyring/list-secret-keys secring)]
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
         :created-at #inst "2013-12-27T18:42:31.000-00:00"
         :revoked? false
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
         :created-at #inst "2013-12-27T18:42:31.000-00:00"
         :revoked? false
         :encryption-key? true
         :signing-key? true}]
    (doseq [[k v] expected]
      (is (= v (get info k))))))


(deftest public-key-encoding
  (testing "binary"
    (let [encoded-key (pgp/encode pubkey)
          decoded-key (pgp/decode-public-key encoded-key)]
      (is (instance? PGPPublicKey decoded-key)
          "key is decoded as a PGP public key")
      (is (bytes= encoded-key (pgp/encode decoded-key))
          "encoded key is canonical")))
  (testing "ascii"
    (let [encoded-key (pgp/encode-ascii pubkey)
          decoded-key (pgp/decode-public-key encoded-key)]
      (is (string? encoded-key)
          "key is encoded as a string")
      (is (instance? PGPPublicKey decoded-key)
          "key is decoded as a PGP public key")
      (is (= encoded-key (pgp/encode-ascii decoded-key))
          "encoded key is canonical"))))


; TODO: keyring encoding tests
