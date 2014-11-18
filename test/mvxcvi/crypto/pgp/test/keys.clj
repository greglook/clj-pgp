(ns mvxcvi.crypto.pgp.test.keys
  (:require
    [clojure.java.io :as io]
    [clojure.test.check.generators :as gen]
    [mvxcvi.crypto.pgp :as pgp]
    (mvxcvi.crypto.pgp
      [generate :as pgp-gen]
      [tags :as tags])))


;; ## Keyring Fixtures

(def pubring
  (-> "mvxcvi/crypto/pgp/test/keys/pubring.gpg"
      io/resource
      io/file
      pgp/load-public-keyring))


(def secring
  (-> "mvxcvi/crypto/pgp/test/keys/secring.gpg"
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



;; ## Generative Utilities

(defn gen-subseq
  "Returns a generator for sequences of unique values from the keys of the
  passed map."
  [m]
  (gen/fmap
    #(take % (shuffle (keys m)))
    (gen/choose 0 (count m))))


(def gen-mastersig
  "Generator for master key signature generators."
  (gen/fmap
    (fn [[hash-prefs symmetric-prefs zip-prefs]]
      (doto (pgp-gen/signature-generator :master)
        (pgp-gen/prefer-hash-algorithms! hash-prefs)
        (pgp-gen/prefer-symmetric-algorithms! symmetric-prefs)
        (pgp-gen/prefer-compression-algorithms! zip-prefs)))
    (gen/tuple (gen-subseq tags/hash-algorithms)
               (gen-subseq tags/symmetric-key-algorithms)
               (gen-subseq tags/compression-algorithms))))


(defn gen-rsa-keyspec
  "Returns a generator for RSA keys with the given algorithms."
  [algos strengths]
  (gen/tuple
    (gen/return :rsa)
    (gen/elements algos)
    (gen/elements strengths)))


(defn spec->keypair
  "Generates a keypair from a keyspec."
  [[key-type & spec]]
  (case key-type
    :rsa (let [[algo strength] spec
               rsa (pgp-gen/rsa-keypair-generator strength)]
           (pgp-gen/generate-keypair rsa algo))))
