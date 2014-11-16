(ns mvxcvi.crypto.pgp.generate-test
  (:require
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
      PGPSecretKeyRing)))


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


(defn gen-rsa-keypair
  "Returns a generator for RSA keypairs with bit strengths chosen from the
  given argument."
  ([algo]
   (gen-rsa-keypair algo [512 1024 2048]))
  ([algo strengths]
   (gen/fmap
     (fn [strength]
       (println "Generating" strength "bit" algo)
       (pgp-gen/generate-keypair
         (pgp-gen/rsa-keypair-generator strength)
         algo))
     (gen/elements strengths))))


(defn gen-keypair
  "Returns a generator for keypairs of the given type."
  [key-type]
  (gen/bind
    (gen/elements
      (case key-type
        :signing    [:rsa-sign]
        :encryption [:rsa-encrypt]))
    (fn [algo]
      (println "Making keypair generator for" algo)
      (case algo
        (:rsa-sign :rsa-encrypt)
        (gen-rsa-keypair algo)))))


(defn gen-keyring-gen
  "Returns a new keyring generator using the given user-id and passphrase."
  [user-id passphrase]
  (gen/fmap
    (partial apply
       pgp-gen/keyring-generator
       user-id passphrase)
    (gen/tuple
      (gen-keypair :signing)
      gen-mastersig)))


(def gen-subkey
  "Generator for pairs of keypairs and corresponding signature generators."
  ; TODO: key expiry?
  (gen/bind
    (gen/elements [:signing :encryption])
    #(gen/tuple (gen-keypair %)
                (gen/fmap pgp-gen/signature-generator
                          (gen/return %)))))


(defn gen-keyrings
  "Returns a new generator for a keyring with some subkeys the returned map
  will contain a :user-id and :passphrase key as well."
  [[user-id passphrase]]
  (gen/fmap
    (fn [[krg subkeys]]
      (doseq [[keypair siggen] subkeys]
        (pgp-gen/add-subkey! krg keypair siggen))
      (assoc
        (pgp-gen/generate-keyrings krg)
        :user-id user-id
        :passphrase passphrase))
    (gen/tuple
      (gen-keyring-gen user-id passphrase)
      (gen/vector gen-subkey))))


(def keypair-property
  (prop/for-all [algo     (gen/elements [:rsa-sign :rsa-encrypt])
                 strength (gen/elements [512 1024 2048])
                 data     gen/bytes]
    (let [rsa (pgp-gen/rsa-keypair-generator strength)
          keypair (pgp-gen/generate-keypair rsa algo)]
      (fact (str strength " bit " algo " keypair")
        ; TODO: if signing key, sign data, check signature
        ; TODO: if encryption key, encrypt data, decrypt data
        ))))
