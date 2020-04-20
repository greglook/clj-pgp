(ns clj-pgp.test.encryption
  (:require
    [byte-streams :refer [bytes=] :as bytes]
    [clj-pgp.core :as pgp]
    [clj-pgp.error :as error]
    [clj-pgp.generate :as pgp-gen]
    [clj-pgp.message :as pgp-msg]
    [clj-pgp.test.keys :refer
     [gen-ec-keyspec
      gen-rsa-keyspec
      spec->keypair
      memospec->keypair]]
    [clojure.test :refer [deftest testing is]]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop])
  (:import
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
     (gen/elements (cons nil pgp/compression-algorithms))
     (gen/elements (remove #{:null :safer :camellia-256} pgp/symmetric-key-algorithms))
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
      (let [envelope (pgp-msg/package data)]
        (is (not (bytes= data envelope))
            "Message should wrap a literal packet around the data.")
        (is (bytes= data (:data (first (pgp-msg/read-messages envelope))))
            "Literal packet message should be readable with no decryptors.")))
    (let [ciphertext (pgp-msg/encrypt data keypair)]
      (is (bytes= data (pgp-msg/decrypt ciphertext (constantly keypair)))
          "Decrypting with a keypair-retrieval function returns the data.")
      (is (thrown? IllegalArgumentException
            (pgp-msg/decrypt ciphertext "passphrase"))
          "Decrypting without a matching key throws an exception")
      (testing "should allow overriding error behavior with custom behavior"
        (let [error-occured? (atom false)
              error-handler (fn [_ _ _ _]
                              (reset! error-occured? true)
                              nil)]
          (with-redefs [pgp/read-next-object (fn [_] (throw (Exception. "Simulating PGP nextObject error")))]
            (binding [error/*handler* error-handler]
              (pgp-msg/decrypt ciphertext (constantly keypair))
              (is @error-occured? "A PGP error was simulated but not passed to the error handler."))))))))


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


(defn- test-multiple-packages-scenario
  [data encryptor & opts]
  (let [packages (for [data (repeat 3 data)]
                   (apply pgp-msg/package data :encryptors [encryptor] opts))]
    (is
      (every?
        (fn check-message
          [message]
          (bytes= data (:data message)))
        (apply pgp-msg/read-messages (bytes/to-input-stream packages) :decryptor encryptor opts)))))


(deftest multiple-packages
  (testing "PBE encryption"
    (test-multiple-packages-scenario
      "Secret stuff to hide from prying eyes"
      "s3cr3t"))
  (testing "compressed PBE encrpytion"
    (test-multiple-packages-scenario
      "secrets"
      "p@ssw0rdz"
      :compress :zip))
  (testing "compressed RSA key encryption"
    (test-multiple-packages-scenario
      "More secretz"
      (spec->keypair [:rsa :rsa-general 1024])
      :compress :zip))
  (testing "RSA key encryption"
    (test-multiple-packages-scenario
      "RSA secrets"
      (spec->keypair [:rsa :rsa-general 1024]))))
