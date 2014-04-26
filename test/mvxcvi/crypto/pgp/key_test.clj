(ns mvxcvi.crypto.pgp.key-test
  (:require
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)))


(def test-keyring
  (-> "test-resources/pgp/secring.gpg"
      io/resource
      io/file
      pgp/load-secret-keyring))


(deftest public-key-functions
  (let [hex-id "923b1c1c4392318a"
        pubkey (pgp/get-public-key test-keyring hex-id)]
    (is (instance? PGPPublicKey (pgp/public-key test-keyring)))
    (is (identical? pubkey (pgp/public-key pubkey)))
    (is (= (pgp/key-id hex-id) (pgp/key-id pubkey)))
    (let [info (pgp/key-info pubkey)]
      (are [k v] (= v (info k))
        :key-id hex-id
        :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A"
        :algorithm :rsa-general
        :strength 1024
        :master-key? true
        :encryption-key? true
        :user-ids ["Test User <test@vault.mvxcvi.com>"]))))


(deftest secret-key-functions
  (let [hex-id "3f40edec41c6cb7d"
        seckey (pgp/get-secret-key test-keyring hex-id)]
    (is (instance? PGPSecretKey (pgp/secret-key test-keyring)))
    (is (identical? seckey (pgp/secret-key seckey)))
    (is (= (pgp/key-id hex-id)
           (pgp/key-id seckey)
           (pgp/key-id (pgp/public-key seckey))))
    (is (= :rsa-general (pgp/key-algorithm seckey)))
    (let [info (pgp/key-info seckey)]
      (are [k v] (= v (info k))
        :key-id "3f40edec41c6cb7d"
        :fingerprint "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
        :algorithm :rsa-general
        :strength 1024
        :master-key? false
        :secret-key? true
        :encryption-key? true
        :signing-key? true))))


(deftest private-key-functions
  (let [hex-id "3f40edec41c6cb7d"
        seckey (pgp/get-secret-key test-keyring hex-id)
        privkey (pgp/unlock-key seckey "test password")]
    (is (instance? PGPPrivateKey privkey))
    (is (= (pgp/key-id seckey) (pgp/key-id privkey)))
    (is (= :rsa-general (pgp/key-algorithm privkey)))
    (is (thrown? Exception (pgp/unlock-key seckey "wrong password")))))


(deftest key-id-coercion
  (is (nil? (pgp/key-id nil)))
  (is (= 1234 (pgp/key-id 1234))))


(deftest key-algorithm-coercion
  (is (nil? (pgp/key-algorithm nil)))
  (is (= :rsa-general (pgp/key-algorithm :rsa-general))))
