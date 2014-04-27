(ns mvxcvi.crypto.pgp.test-keys
  (:require
    [clojure.java.io :as io]
    [mvxcvi.crypto.pgp :as pgp]))


(def pubring
  (-> "mvxcvi/crypto/pgp/test_keys/pubring.gpg"
      io/resource
      io/file
      pgp/load-public-keyring))


(def secring
  (-> "mvxcvi/crypto/pgp/test_keys/secring.gpg"
      io/resource
      io/file
      pgp/load-secret-keyring))
