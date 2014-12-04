(ns clj-pgp.test.encryption
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [clojure.test.check :as check]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]
    (clj-pgp
      [core :as pgp]
      [generate :as pgp-gen]
      [message :as pgp-msg]
      [tags :as tags])
    [clj-pgp.test.keys :refer
     [gen-ec-keyspec
      gen-rsa-keyspec
      memospec->keypair]])
  (:import
    java.io.ByteArrayOutputStream
    java.security.SecureRandom))


(defn test-encryption-scenario
  "Tests that encrypting and decrypting data with the given keypairs/passphrases
  returns the original data."
  [keyspecs data compress cipher armor]
  (testing (str "Encrypting " (count data) " bytes with " cipher
                " for keys " (pr-str keyspecs)
                (when compress (str " compressed with " compress))
                " encoded in " (if armor "ascii" "binary"))
    (let [encryptors (map memospec->keypair keyspecs)
          ciphertext (pgp-msg/encrypt
                       data encryptors
                       :compress compress
                       :cipher cipher
                       :armor armor)]
      (is (not (bytes= data ciphertext))
        "ciphertext bytes differ from data")
      (doseq [decryptor encryptors]
        (is (bytes= data (pgp-msg/decrypt ciphertext decryptor))
            "decrypting the ciphertext returns plaintext"))
      [encryptors ciphertext])))


(def gen-encryptors
  (->>
    (gen/tuple
      gen/boolean
      (gen/not-empty gen/string-ascii)
      (gen/vector
        (gen/one-of
          [(gen-rsa-keyspec [1024 2048 4096])
           (gen-ec-keyspec :ecdh pgp-gen/elliptic-curve-names)])))
    (gen/fmap
      (fn [[p pass keypairs]]
        (-> (if p
              (cons pass keypairs)
              keypairs)
            set shuffle)))
    gen/not-empty))


(def data-encryption-property
  (prop/for-all*
    [gen-encryptors
     (gen/not-empty gen/bytes)
     (gen/elements (cons nil (keys tags/compression-algorithms)))
     (gen/elements (remove #{:null :safer :camellia-256} (keys tags/symmetric-key-algorithms)))
     gen/boolean]
    test-encryption-scenario))


(deftest pgp-messages
  (let [rsa (pgp-gen/rsa-keypair-generator 1024)
        keypair (pgp-gen/generate-keypair rsa :rsa-general)
        data "My hidden data files"]
    (is (thrown? IllegalArgumentException
          (pgp-msg/encrypted-data-stream nil :aes-128 []))
        "Encryption with no encryptors throws an exception")
    (is (thrown? IllegalArgumentException
          (pgp-msg/encrypt data :not-an-encryptor
                       :integrity-check false
                       :random (SecureRandom.)))
        "Encryption with an invalid encryptor throws an exception")
    (is (thrown? IllegalArgumentException
          (pgp-msg/encrypt data ["bar" "baz"]))
        "Encryption with multiple passphrases throws an exception")
    (testing "uncompressed unenciphered data"
      (let [message (pgp-msg/build-message data)]
        (is (not (bytes= data message))
            "Message should wrap a literal packet around the data.")
        (is (bytes= data (pgp-msg/read-message message))
            "Literal packet message should be readable with no decryptors.")))
    (let [ciphertext (pgp-msg/encrypt data keypair)]
      (is (bytes= data (pgp-msg/decrypt ciphertext (constantly keypair)))
          "Decrypting with a keypair-retrieval function returns the data.")
      (is (thrown? IllegalArgumentException
            (pgp-msg/decrypt ciphertext "passphrase"))
          "Decrypting without a matching key throws an exception"))))


(deftest encryption-scenarios
  (testing "passphrase-only encryption"
    (test-encryption-scenario
      ["s3cr3t"]
      "The data blobble"
      nil :aes-128 true))
  (testing "RSA key encryption"
    (test-encryption-scenario
      [[:rsa :rsa-encrypt 1024]]
      "Secret stuff to hide from prying eyes"
      nil :aes-128 false))
  (testing "ECDH key encryption"
    (test-encryption-scenario
      [[:ec :ecdh "secp256r1"]]
      "Foooooood is nice"
      :zip :aes-256 true))
  (testing "passphrase and multi-key encryption"
    (test-encryption-scenario
      ["frobble bisvarkian"
       [:rsa :rsa-general 1024]
       [:ec :ecdh "sect409r1"]]
      "Good news, everyone!"
      :bzip2 :aes-256 true)))
