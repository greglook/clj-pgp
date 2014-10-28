(ns mvxcvi.crypto.pgp.keyring-test
  (:require
    [clojure.java.io :as io]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]))


(facts "public keyrings"
  (let [keyring (-> "mvxcvi/crypto/pgp/test_keys/pubring.gpg"
                    io/resource
                    io/file
                    pgp/load-public-keyring)
        pubkeys (pgp/list-public-keys keyring)]
    (fact "test public keyring contains two keys"
      (count pubkeys) => 2)))


(facts "secret keyrings"
  (let [keyring (-> "mvxcvi/crypto/pgp/test_keys/secring.gpg"
                    io/resource
                    io/file
                    pgp/load-secret-keyring)
        pubkeys (pgp/list-public-keys keyring)
        seckeys (pgp/list-secret-keys keyring)]
    (fact "test secret keyring contains two keys"
      (count pubkeys) => 2
      (count seckeys) => 2)))
