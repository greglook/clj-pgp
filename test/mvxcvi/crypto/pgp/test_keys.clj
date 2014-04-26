(ns mvxcvi.crypto.pgp.test-keys
  (:require
    [clojure.java.io :as io]
    [mvxcvi.crypto.pgp :as pgp]))


(def pubring
  (-> "test-resources/pgp/pubring.gpg"
      io/resource
      io/file
      pgp/load-public-keyring))


(def secring
  (-> "test-resources/pgp/secring.gpg"
      io/resource
      io/file
      pgp/load-secret-keyring))
