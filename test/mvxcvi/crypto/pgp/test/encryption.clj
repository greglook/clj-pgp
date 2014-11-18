(ns mvxcvi.crypto.pgp.test.encryption
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.test.check :as check]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    (mvxcvi.crypto.pgp
      [generate :as pgp-gen]
      [tags :as tags])))


(comment "Move these"

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


  (defn gen-keypair
    [algo strength]
    (case algo
      (:rsa-encrypt :rsa-sign :rsa-general)
      (pgp-gen/generate-keypair
        (pgp-gen/rsa-keypair-generator strength)
        algo))))


(defn test-encryption-keypair
  "Tests that encrypting and decrypting data with the given keypair returns
  the original data."
  [keypair data & {:keys [zip-algo sym-algo armor]
                   :or {sym-algo :aes-256}}]
  (facts (str (pgp/key-algorithm keypair) " keypair encrypting "
              (count data) " bytes with " sym-algo
              (when zip-algo (str " compressed with " zip-algo))
              " encoded in " (if armor "ascii" "binary"))
    (fact "keypair is capable of encryption"
      (pgp/key-info keypair)
      => (contains {:encryption-key? true}))
    (let [ciphertext (pgp/encrypt
                       data keypair
                       :algorithm sym-algo
                       :compress zip-algo
                       :armor armor)]
      (fact "ciphertext bytes differ from data"
        ciphertext =not=> (partial bytes= data))
      (fact "decrypting the ciphertext returns plaintext"
        (pgp/decrypt ciphertext (constantly keypair))
        => (partial bytes= data)))))


(def keypair-encryption-property
  (prop/for-all
    [key-algo (gen/elements [:rsa-encrypt :rsa-general])
     strength (gen/elements [512 1024 2048])
     data     gen/bytes
     zip-algo (gen/elements (cons nil (keys tags/compression-algorithms)))
     sym-algo (gen/elements (remove #{:null :safer} (keys tags/symmetric-key-algorithms)))
     armor    gen/boolean]
    (let [rsa (pgp-gen/rsa-keypair-generator strength)
          keypair (pgp-gen/generate-keypair rsa key-algo)]
      (test-encryption-keypair
        keypair data
        :zip-algo zip-algo
        :sym-algo sym-algo
        :armor armor))))


(facts "Generative encryption testing"
  (check/quick-check 5 keypair-encryption-property)
  => (contains {:result true}))
