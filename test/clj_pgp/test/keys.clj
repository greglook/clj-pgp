(ns clj-pgp.test.keys
  (:require
    [clj-pgp.core :as pgp]
    [clj-pgp.generate :as pgp-gen]
    [clj-pgp.keyring :as keyring]
    [clojure.java.io :as io]
    [clojure.test.check.generators :as gen]))


;; ## Keyring Fixtures

(def pubring
  (-> "clj_pgp/test/keys/pubring.gpg"
      io/resource
      io/file
      keyring/load-public-keyring))


(def secring
  (-> "clj_pgp/test/keys/secring.gpg"
      io/resource
      io/file
      keyring/load-secret-keyring))


(defn get-privkey
  [id]
  (some-> secring
          (keyring/get-secret-key id)
          (pgp/unlock-key "test password")))


(def master-pubkey (keyring/get-public-key pubring "923b1c1c4392318a"))

(def pubkey  (keyring/get-public-key secring "3f40edec41c6cb7d"))
(def seckey  (keyring/get-secret-key secring pubkey))
(def privkey (pgp/unlock-key seckey "test password"))



;; ## Generative Utilities

(defn gen-rsa-keyspec
  "Returns a generator for RSA keys with the given strengths."
  [strengths]
  (gen/fmap
    (partial vector :rsa :rsa-general)
    (gen/elements strengths)))


(defn gen-ec-keyspec
  "Returns a generator for EC keys with the given algorithm and named curves."
  [algorithm curves]
  (gen/fmap
    (partial vector :ec algorithm)
    (gen/elements curves)))


(defn spec->keypair
  "Generates a keypair from a keyspec."
  [[key-type & opts]]
  (case key-type
    :rsa (let [[algo strength] opts
               rsa (pgp-gen/rsa-keypair-generator strength)]
           (pgp-gen/generate-keypair rsa algo))
    :ec (let [[algo curve] opts
              ec (pgp-gen/ec-keypair-generator curve)]
          (pgp-gen/generate-keypair ec algo))))


(def key-cache
  "Stores generated keys by their key-specs to memoize key generation calls."
  (atom {}))


(defn memospec->keypair
  "Returns a keypair for a keyspec. Uses the key-cache var to memoize the
  generated keys."
  [spec]
  (or (when (string? spec) spec)
      (get @key-cache spec)
      (let [k (spec->keypair spec)]
        (swap! key-cache assoc spec k)
        k)))
