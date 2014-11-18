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
      [tags :as tags])
    [mvxcvi.crypto.pgp.test.keys :refer
     [spec->keypair gen-rsa-keyspec]]))


(defn test-encryption-keypair
  "Tests that encrypting and decrypting data with the given keypair returns
  the original data."
  [keyspec data zip-algo sym-algo armor]
  (facts (str "Keypair " (pr-str keyspec) " encrypting "
              (count data) " bytes with " sym-algo
              (when zip-algo (str " compressed with " zip-algo))
              " encoded in " (if armor "ascii" "binary"))
    (let [keypair (spec->keypair keyspec)
          ciphertext (pgp/encrypt
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
  (prop/for-all*
    [(gen-rsa-keyspec [:rsa-encrypt :rsa-general] [512 1024 2048])
     gen/bytes
     (gen/elements (cons nil (keys tags/compression-algorithms)))
     (gen/elements (remove #{:null :safer} (keys tags/symmetric-key-algorithms)))
     gen/boolean]
    test-encryption-keypair))


(facts "Generative encryption testing"
  (test-encryption-keypair
    [:rsa :rsa-encrypt 1024]
    "Secret stuff to hide from prying eyes"
    nil :aes-128 false)
  (test-encryption-keypair
    [:rsa :rsa-general 4096]
    "My hidden data files"
    :zip :aes-256 true))
