(ns mvxcvi.crypto.pgp.generate
  (:require
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [key :refer [key-algorithm]]
      [tags :as tags]))
  (:import
    java.security.SecureRandom
    java.util.Date
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
      PGPKeyPair
      PGPKeyRingGenerator
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


(defn- secret-key-encryptor
  "Constructs a new encryptor which will lock secret keys with the given
  passphrase. The encryption algorithm and passphrase hash algorithm may be
  specified as optional keyword arguments."
  [^String passphrase
   & {:keys [enc-algorithm pass-algorithm]
      :or {enc-algorithm :aes-256
           pass-algorithm :sha256}}]
  (.build (BcPBESecretKeyEncryptorBuilder.
             (tags/symmetric-key-algorithm :aes-256)
             (digest-calculator :sha256))
           (.toCharArray passphrase)))


(defn- rsa-keypair-generator
  "Constructs a new generator for RSA keypairs with the given bit strength.
  Other parameters may be customized with keyword options."
  ^RSAKeyPairGenerator
  [strength & {:keys [exponent random certainty]
               :or {exponent (BigInteger/valueOf 0x10001)
                    random (SecureRandom.)
                    certainty 80}}]
  (doto (RSAKeyPairGenerator.)
    (.init (RSAKeyGenerationParameters. exponent random strength certainty))))


(defn- generate-keypair
  "Builds a new PGP keypair from a generator."
  ^PGPKeyPair
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


(defn- prefer-algorithms!
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


(defn keyring-generator
  ^PGPKeyRingGenerator
  [^PGPKeyPair master-key
   ^String user-id
   ^String passphrase]
  (let [master-sig-gen  ; Add a self-signature on the user-id.
        (doto (signature-subpacket-generator
                KeyFlags/SIGN_DATA
                KeyFlags/CERTIFY_OTHER)
          (prefer-algorithms!
            :symmetric [:aes-256 :aes-192 :aes-128]
            :hash [:sha512 :sha384 :sha256 :sha224 :sha1]
            :compression [:zlib :bzip2 :zip :uncompressed])
          ; Request senders add additional checksums to the message (useful
          ; when verifying unsigned messages).
          (.setFeature false Features/FEATURE_MODIFICATION_DETECTION))]
    (PGPKeyRingGenerator.
      PGPSignature/POSITIVE_CERTIFICATION
      master-key
      user-id
      (digest-calculator :sha1)
      (.generate master-sig-gen)
      nil
      (BcPGPContentSignerBuilder.
        (key-algorithm master-key)
        (tags/hash-algorithm :sha1))
      (secret-key-encryptor passphrase))))


(defn add-encryption-subkey!
  [^PGPKeyRingGenerator generator
   ^PGPKeyPair subkey]
  (.addSubKey generator
    subkey
    (.generate (signature-subpacket-generator
                 KeyFlags/ENCRYPT_COMMS
                 KeyFlags/ENCRYPT_STORAGE))
    nil))


(defn add-signing-subkey!
  [^PGPKeyRingGenerator generator
   ^PGPKeyPair subkey]
  (.addSubKey generator
    subkey
    (.generate (signature-subpacket-generator
                 KeyFlags/SIGN_DATA))
    nil))


(defn generate-keyrings
  [user-id passphrase]
  (let [kpg (rsa-keypair-generator 1024)
        master-key (generate-keypair kpg :rsa-sign)
        krg (keyring-generator master-key user-id passphrase)]
    (add-encryption-subkey! krg (generate-keypair kpg :rsa-encrypt))
    (add-signing-subkey! krg (generate-keypair kpg :rsa-sign))
    {:public (.generatePublicKeyRing krg)
     :secret (.generateSecretKeyRing krg)}))
