(ns mvxcvi.crypto.pgp.generate
  (:require
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [tags :as tags]
      [util :refer [hex-str]]))
  (:import
    (java.security
      SecureRandom)
    (java.util
      Date)
    (org.bouncycastle.bcpg.sig
      Features
      KeyFlags)
    (org.bouncycastle.crypto
      AsymmetricCipherKeyPairGenerator)
    (org.bouncycastle.crypto.generators
      RSAKeyPairGenerator)
    (org.bouncycastle.crypto.params
      RSAKeyGenerationParameters)
    (org.bouncycastle.openpgp
      PGPEncryptedData
      PGPKeyPair
      PGPPublicKeyRing
      PGPKeyRingGenerator
      PGPPublicKey
      PGPSecretKey
      PGPSecretKeyRing
      PGPSignature
      PGPSignatureSubpacketGenerator)
    (org.bouncycastle.openpgp.operator
      PBESecretKeyEncryptor
      PGPDigestCalculator)
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyEncryptorBuilder
      BcPGPContentSignerBuilder
      BcPGPDigestCalculatorProvider
      BcPGPKeyPair)))


;; ## Key Generation

(defn- digest-calculator
  "Constructs a new digest calculator for the given hash algorithm."
  ^PGPDigestCalculator
  [algorithm]
  (.get (BcPGPDigestCalculatorProvider.)
        (tags/hash-algorithm algorithm)))


(defn- rsa-keypair-generator
  "Constructs a new generator for RSA keypairs with the given bit strength.
  A custom random number generator may be given as an optional argument."
  (^RSAKeyPairGenerator
   [strength]
   (rsa-keypair-generator strength (SecureRandom/getInstance "SHA1PRNG")))
  (^RSAKeyPairGenerator
   [strength random]
   (doto (RSAKeyPairGenerator.)
     (.init (RSAKeyGenerationParameters.
              (BigInteger/valueOf 0x10001)
              random
              strength
              80)))))


(defn- generate-keypair
  "Builds a new PGP keypair from a generator."
  [^AsymmetricCipherKeyPairGenerator generator
   algorithm]
  (BcPGPKeyPair.
    (tags/public-key-algorithm algorithm)
    (.generateKeyPair generator)
    (Date.)))


(defn- signature-subpacket-generator
  "Constructs a new generator for key signature subpackets. The given flags
  will be applied to the key."
  ^PGPSignatureSubpacketGenerator
  [& flags]
  (let [generator (PGPSignatureSubpacketGenerator.)]
    (when (seq flags)
      (.setKeyFlags generator false (apply bit-or flags)))
    generator))


(defn- prefer-algorithms
  "Sets preferences on a signature generator for secondary cryptographic
  algorithms to use when messages are sent to a keypair."
  [^PGPSignatureSubpacketGenerator generator
   & {:as algorithms}]
  (when-let [algos (:symmetric algorithms)]
    (.setPreferredSymmetricAlgorithms
      generator
      false
      (int-array (map tags/symmetric-key-algorithm algos))))
  (when-let [algos (:hash algorithms)]
    (.setPreferredHashAlgorithms
      generator
      false
      (int-array (map tags/hash-algorithm algos))))
  (when-let [algos (:compression algorithms)]
    (.setPreferredCompressionAlgorithms
      generator
      false
      (int-array (map tags/compression-algorithm algos)))))


(defn- keyring-generator
  ^PGPKeyRingGenerator
  [^PGPKeyPair master-key
   ^String user-id
   ^String passphrase]
  (let [master-sig-gen  ; Add a self-signature on the user-id.
        (doto (signature-subpacket-generator
                KeyFlags/SIGN_DATA
                KeyFlags/CERTIFY_OTHER)
          (prefer-algorithms
            :symmetric [:aes-256 :aes-192 :aes-128]
            :hash [:sha512 :sha384 :sha256 :sha224 :sha1]
            :compression [:zlib :bzip2 :zip :uncompressed])
          ; Request senders add additional checksums to the message (useful
          ; when verifying unsigned messages).
          (.setFeature false Features/FEATURE_MODIFICATION_DETECTION))

        secret-encryptor (.build (BcPBESecretKeyEncryptorBuilder.
                                   (int (tags/symmetric-key-algorithm :aes-256))
                                   (digest-calculator :sha256))
                                 (.toCharArray passphrase))]

    (PGPKeyRingGenerator.
      PGPSignature/POSITIVE_CERTIFICATION
      master-key
      user-id
      (digest-calculator :sha1)
      (.generate master-sig-gen)
      nil
      (BcPGPContentSignerBuilder.
        (.getAlgorithm (.getPublicKey master-key))  ; TODO: use coercion multimethods
        (tags/hash-algorithm :sha1))
      secret-encryptor)))


(defn- add-encryption-subkey
  [^PGPKeyRingGenerator generator
   ^PGPKeyPair subkey]
  (.addSubKey generator
    subkey
    (.generate (signature-subpacket-generator
                 KeyFlags/ENCRYPT_COMMS
                 KeyFlags/ENCRYPT_STORAGE))
    nil))


(defn generate-keyrings
  [user-id passphrase]
  (let [kpg (rsa-keypair-generator 1024)
        master-key (generate-keypair kpg :rsa-sign)
        krg (keyring-generator master-key user-id passphrase)]
    (add-encryption-subkey krg (generate-keypair kpg :rsa-encrypt))
    {:public (.generatePublicKeyRing krg)
     :secret (.generateSecretKeyRing krg)}))
