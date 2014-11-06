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
  [^String user-id
   ^String passphrase]
  (let [kpg (rsa-keypair-generator 1024)

        ; Generate a master signing key.
        master-keys (BcPGPKeyPair.
                      PGPPublicKey/RSA_SIGN
                      (.generateKeyPair kpg)
                      (Date.))

        ; Generate an encryption subkey.
        enc-keys (BcPGPKeyPair.
                   PGPPublicKey/RSA_ENCRYPT
                   (.generateKeyPair kpg)
                   (Date.))

        ; Add a self-signature on the user-id.
        master-sig-gen
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

        ; Create a signature on the encryption subkey.
        enc-sig-gen
        (signature-subpacket-generator
          KeyFlags/ENCRYPT_COMMS
          KeyFlags/ENCRYPT_STORAGE)

        sha1-calc   (.get (BcPGPDigestCalculatorProvider.) (tags/hash-algorithm :sha1))
        sha256-calc (.get (BcPGPDigestCalculatorProvider.) (tags/hash-algorithm :sha256))

        secret-encryptor (.build (BcPBESecretKeyEncryptorBuilder.
                                   PGPEncryptedData/AES_256
                                   sha256-calc)
                                 (.toCharArray passphrase))

        ; Finally, create the keyring itself.
        keyring-gen (PGPKeyRingGenerator.
                      PGPSignature/POSITIVE_CERTIFICATION
                      master-keys
                      user-id
                      sha1-calc
                      (.generate master-sig-gen)
                      nil
                      (BcPGPContentSignerBuilder.
                        (.getAlgorithm (.getPublicKey master-keys))  ; TODO: use coercion multimethods
                        (tags/hash-algorithm :sha1))
                      secret-encryptor)
        ]
        (doto keyring-gen
          ; Add our encryption subkey, together with its signature.
          (.addSubKey enc-keys (.generate enc-sig-gen) nil))))


(defn generate-keyrings
  [user-id passphrase]
  (let [krg (keyring-generator user-id passphrase)]
    {:public (.generatePublicKeyRing krg)
     :secret (.generateSecretKeyRing krg)}))
