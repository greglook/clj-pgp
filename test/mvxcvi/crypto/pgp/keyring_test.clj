(ns mvxcvi.crypto.pgp.keyring-test
  (:require
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]))


(deftest public-keyring
  (let [keyring (-> "test-resources/pgp/pubring.gpg"
                    io/resource
                    io/file
                    pgp/load-public-keyring)
        pubkeys (pgp/list-public-keys keyring)]
    (is (= 2 (count pubkeys)))
    (is (= (first pubkeys)
           (pgp/get-public-key keyring (first pubkeys))))))


(deftest secret-keyring
  (let [keyring (-> "test-resources/pgp/secring.gpg"
                    io/resource
                    io/file
                    pgp/load-secret-keyring)
        pubkeys (pgp/list-public-keys keyring)
        seckeys (pgp/list-secret-keys keyring)]
    (is (= 2 (count pubkeys) (count seckeys)))
    (is (= (first pubkeys)
           (pgp/get-public-key keyring (first pubkeys))))
    (is (= (first seckeys)
           (pgp/get-secret-key keyring (first seckeys))))))
