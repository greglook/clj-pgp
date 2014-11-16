(ns mvxcvi.crypto.pgp.generate-test
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.test.check :as check]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    (mvxcvi.crypto.pgp
      [generate :as pgp-gen]
      [tags :as tags]))
  (:import
    java.security.SecureRandom
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPSecretKeyRing))
  (:gen-class))


;; ## Macro Expansion

(facts "Keyring macro generation"
  (fact "A master-key spec is required."
    (eval '(pgp-gen/generate-keys ..user-id.. ..passphrase..))
    => (throws Exception))

  (fact "Multiple master-key specs are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             (master-key ..keypair-2..)))
    => (throws Exception))

  (fact "Malformed subkey specs are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             ..some-val..))
    => (throws Exception))

  (fact "Unknown subkey spec types are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key ..keypair-1..)
             (foobar-key ..keypair-2..)))
    => (throws Exception))

  (fact "Malformed signature subpackets are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key
               ..keypair-1..
               ..some-val..)))
    => (throws Exception))

  (fact "Unknown signature subpacket types are illegal."
    (eval '(pgp-gen/generate-keys
             ..user-id.. ..passphrase..
             (master-key
               ..keypair-1..
               (foobar-option ..arg..))))
    => (throws Exception))

  (fact "Full macro expansion."
    (pgp-gen/generate-keys
      ..user-id.. ..passphrase..
      (master-key
        (keypair ..rsa.. :rsa-sign)
        (prefer-hash :sha512 :sha384 :sha256 :sha224 :sha1)
        (prefer-symmetric :aes-256 :aes-192 :aes-128)
        (prefer-compression :zlib :bzip2 :zip :uncompressed))
      (signing-key
        ..signing-keypair..
        (expires 3600))
      (encryption-key
        (keypair ..rsa.. :rsa-encrypt)))

    =expands-to=>

    (mvxcvi.crypto.pgp.generate/generate-keyrings
      (clojure.core/doto
        (mvxcvi.crypto.pgp.generate/keyring-generator
          ..user-id.. ..passphrase..
          (mvxcvi.crypto.pgp.generate/generate-keypair ..rsa.. :rsa-sign)
          (clojure.core/doto
            (mvxcvi.crypto.pgp.generate/signature-generator :master)
            (mvxcvi.crypto.pgp.generate/prefer-hash-algorithms! :sha512 :sha384 :sha256 :sha224 :sha1)
            (mvxcvi.crypto.pgp.generate/prefer-symmetric-algorithms! :aes-256 :aes-192 :aes-128)
            (mvxcvi.crypto.pgp.generate/prefer-compression-algorithms! :zlib :bzip2 :zip :uncompressed)))
        (mvxcvi.crypto.pgp.generate/add-subkey!
          ..signing-keypair..
          (clojure.core/doto
            (mvxcvi.crypto.pgp.generate/signature-generator :signing)
            (mvxcvi.crypto.pgp.generate/set-key-expiration! 3600)))
        (mvxcvi.crypto.pgp.generate/add-subkey!
          (mvxcvi.crypto.pgp.generate/generate-keypair ..rsa.. :rsa-encrypt)
          (mvxcvi.crypto.pgp.generate/signature-generator :encryption))))))



;; ## Generative Testing

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


(def keypair-encryption-property
  (prop/for-all [key-algo (gen/elements [:rsa-encrypt])
                 strength (gen/elements [512 1024 2048])
                 data     gen/bytes
                 zip-algo (gen/elements (cons nil (keys tags/compression-algorithms)))
                 sym-algo (gen/elements (remove #{:null :safer} (keys tags/symmetric-key-algorithms)))
                 armor    gen/boolean]
    (facts (str strength " bit " key-algo " keypair encrypting "
                (count data) " bytes with " sym-algo
                (when zip-algo (str " compressed with " zip-algo))
                " encoded in " (if armor "ascii" "binary"))
      (let [rsa (pgp-gen/rsa-keypair-generator strength)
            keypair (pgp-gen/generate-keypair rsa key-algo)
            ciphertext (pgp/encrypt
                         data keypair
                         {:algorithm sym-algo
                          :compress zip-algo
                          :armor armor})]
        (fact "generated keypair is capable of encryption"
          (pgp/key-info keypair) => (contains {:encryption-key? true}))
        (fact "ciphertext bytes differ from data"
          ciphertext =not=> (partial bytes= data))
        (fact "decrypting the ciphertext returns plaintext"
          (pgp/decrypt ciphertext (constantly keypair))
          => (partial bytes= data))))))


(facts "Generative encryption testing"
  (check/quick-check 5 keypair-encryption-property)
  => (contains {:result true}))


(defn -main
  [& [n]]
  (let [n (Integer/parseInt (or n 10))]
    (println "Running property checks for" n "iterations")
    (let [kep (future (check/quick-check n keypair-encryption-property))]
      (println "Keypair Encryption:" (pr-str @kep))
      (shutdown-agents)
      ; TODO: exit with failure code if tests failed
      )))
