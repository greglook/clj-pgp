(ns mvxcvi.crypto.pgp.key-test
  (:require
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]))


(def test-keyring
  (-> "test-resources/pgp/secring.gpg"
      io/resource
      io/file
      pgp/load-secret-keyring))

(def pubkey
  (pgp/get-public-key test-keyring "923b1c1c4392318a"))

(def seckey
  (pgp/get-secret-key test-keyring "3f40edec41c6cb7d"))


(deftest public-key-coercion
  (is (identical? pubkey (pgp/public-key pubkey)))
  (is (thrown? IllegalArgumentException (pgp/public-key "a string"))))


(deftest secret-key-coercion
  #_ ...)


(deftest key-id-coercion
  (is (nil? (pgp/key-id nil)))
  (is (= 1234 (pgp/key-id 1234))))


(deftest key-algorithm-coercion
  (is (nil? (pgp/key-algorithm nil)))
  (is (= :rsa-general (pgp/key-algorithm seckey)))
  (is (= :rsa-general (pgp/key-algorithm :rsa-general))))


(deftest key-info
  (let [info (pgp/key-info pubkey)]
    (are [k v] (= v (info k))
      :key-id "923b1c1c4392318a"
      :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A"
      :algorithm :rsa-general
      :strength 1024
      :master-key? true
      :encryption-key? true
      :user-ids ["Test User <test@vault.mvxcvi.com>"]))
  (let [info (pgp/key-info seckey)]
    (are [k v] (= v (info k))
      :key-id "3f40edec41c6cb7d"
      :fingerprint "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
      :algorithm :rsa-general
      :strength 1024
      :master-key? false
      :secret-key? true
      :encryption-key? true
      :signing-key? true)))
