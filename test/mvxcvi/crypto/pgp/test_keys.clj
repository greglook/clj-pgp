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


(defn get-privkey
  [id]
  (some-> secring
          (pgp/get-secret-key id)
          (pgp/unlock-key "test password")))


(def master-pubkey (pgp/get-public-key pubring "923b1c1c4392318a"))

(def pubkey  (pgp/get-public-key secring "3f40edec41c6cb7d"))
(def seckey  (pgp/get-secret-key secring pubkey))
(def privkey (pgp/unlock-key seckey "test password"))
