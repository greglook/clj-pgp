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


(defn- keyring-generator
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
        ; Add signed metadata on the signature.
        master-sig-gen
        (doto (PGPSignatureSubpacketGenerator.)
          ; 1) Declare its purpose.
          (.setKeyFlags false (bit-or KeyFlags/SIGN_DATA
                                      KeyFlags/CERTIFY_OTHER))
          ; 2) Set preferences for secondary crypto algorithms to use when
          ;    sending messages to this key.
          (.setPreferredSymmetricAlgorithms
            false
            (int-array (map tags/symmetric-key-algorithm [:aes-256 :aes-192 :aes-128])))
          (.setPreferredHashAlgorithms
            false
            (int-array (map tags/hash-algorithm [:sha256 :sha1 :sha384 :sha512 :sha224])))
          ; 3) Request senders add additional checksums to the message (useful
          ;    when verifying unsigned messages).
          (.setFeature false Features/FEATURE_MODIFICATION_DETECTION))

        ; Create a signature on the encryption subkey.
        enc-sig-gen
        (doto (PGPSignatureSubpacketGenerator.)
          (.setKeyFlags false (bit-or KeyFlags/ENCRYPT_COMMS
                                      KeyFlags/ENCRYPT_STORAGE)))

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
