(ns mvxcvi.crypto.pgp.test.encryption
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.test :refer :all]
    [clojure.test.check :as check]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.tags :as tags]
    [mvxcvi.crypto.pgp.test.keys :refer
     [spec->keypair gen-rsa-keyspec]]))


(defn test-encryption-keypair
  "Tests that encrypting and decrypting data with the given keypair returns
  the original data."
  [keyspec test-data zip-algo sym-algo armor]
  (testing (str "Keypair " (pr-str keyspec) " encrypting "
                (count test-data) " blobs with " sym-algo
                (when zip-algo (str " compressed with " zip-algo))
                " encoded in " (if armor "ascii" "binary"))
    (let [keypair (spec->keypair keyspec)]
      (for [data test-data]
        (let [ciphertext (pgp/encrypt
                           data keypair
                           :sym-algo sym-algo
                           :zip-algo zip-algo
                           :armor armor)]
          (is (not (bytes= data ciphertext))
              "ciphertext bytes differ from data")
          (is (bytes= data (pgp/decrypt ciphertext (constantly keypair)))
              "decrypting the ciphertext returns plaintext"))))))


(def keypair-encryption-property
  (prop/for-all*
    [(gen-rsa-keyspec [1024 2048])
     (-> gen/bytes gen/not-empty gen/vector gen/not-empty)
     (gen/elements (cons nil (keys tags/compression-algorithms)))
     (gen/elements (remove #{:null :safer} (keys tags/symmetric-key-algorithms)))
     gen/boolean]
    test-encryption-keypair))


(deftest data-encryption
  (testing "Generative encryption testing"
    (test-encryption-keypair
      [:rsa :rsa-encrypt 1024]
      ["Secret stuff to hide from prying eyes"]
      nil :aes-128 false)
    (test-encryption-keypair
      [:rsa :rsa-general 4096]
      ["My hidden data files"]
      :zip :aes-256 true)))
