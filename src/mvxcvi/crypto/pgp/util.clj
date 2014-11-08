(ns mvxcvi.crypto.pgp.util
  "Utility functions to validate and coerce various kinds of PGP values."
  (:require
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [tags :as tags]))
  (:import
    (org.bouncycastle.openpgp
      PGPKeyPair
      PGPKeyRing
      PGPPrivateKey
      PGPPublicKey
      PGPPublicKeyEncryptedData
      PGPPublicKeyRingCollection
      PGPSecretKey
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPSignature)
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyDecryptorBuilder
      BcPGPDigestCalculatorProvider)))


;; ## Public Key Coercion

(defmulti public-key
  "Returns the PGP public key associated with the argument."
  class)

(defmethod public-key PGPPublicKey
  [^PGPPublicKey pubkey]
  pubkey)

(defmethod public-key PGPSecretKey
  [^PGPSecretKey seckey]
  (.getPublicKey seckey))

(defmethod public-key PGPKeyPair
  [^PGPKeyPair keypair]
  (.getPublicKey keypair))



;; ## Key Identity

(defmulti ^Long key-id
  "Returns the numeric PGP key identifier for the given value."
  class)

(defmethod key-id nil [_] nil)

(defmethod key-id Long [id] id)

(defmethod key-id String
  [^String hex]
  (-> hex (BigInteger. 16) .longValue))

(defmethod key-id PGPPublicKey
  [^PGPPublicKey pubkey]
  (.getKeyID pubkey))

(defmethod key-id PGPSecretKey
  [^PGPSecretKey seckey]
  (.getKeyID seckey))

(defmethod key-id PGPKeyPair
  [^PGPKeyPair keypair]
  (.getKeyID keypair))

(defmethod key-id PGPPrivateKey
  [^PGPPrivateKey privkey]
  (.getKeyID privkey))

(defmethod key-id PGPSignature
  [^PGPSignature sig]
  (.getKeyID sig))

(defmethod key-id PGPPublicKeyEncryptedData
  [^PGPPublicKeyEncryptedData data]
  (.getKeyID data))


(defn hex-id
  "Returns the PGP key identifier for the given value as a hexadecimal string."
  [value]
  (format "%016x" (key-id value)))


(defn hex-fingerprint
  "Returns the PGP key fingerprint as a hexadecimal string."
  [value]
  (let [^PGPPublicKey pubkey (public-key value)]
    (->> (.getFingerprint pubkey)
         (map (partial format "%02X"))
         str/join)))



;; ## Key Algorithms

(defmulti key-algorithm
  "Returns a keyword identifying the public-key algorithm used by the given
  value."
  class)

(defmethod key-algorithm nil [_] nil)

(defmethod key-algorithm clojure.lang.Keyword
  [algorithm]
  (when-not (contains? tags/public-key-algorithms algorithm)
    (throw (IllegalArgumentException.
             (str "Invalid public-key-algorithm name " algorithm))))
  algorithm)

(defmethod key-algorithm Number
  [code]
  (tags/lookup tags/public-key-algorithms code))

(defmethod key-algorithm PGPPublicKey
  [^PGPPublicKey pubkey]
  (key-algorithm (.getAlgorithm pubkey)))

(defmethod key-algorithm PGPSecretKey
  [^PGPSecretKey seckey]
  (key-algorithm (.getPublicKey seckey)))

(defmethod key-algorithm PGPPrivateKey
  [^PGPPrivateKey privkey]
  (key-algorithm (.getAlgorithm (.getPublicKeyPacket privkey))))

(defmethod key-algorithm PGPKeyPair
  [^PGPKeyPair keypair]
  (key-algorithm (.getPublicKey keypair)))



;; ## Key Utilities

; TODO: relocate this?
(defn unlock-key
  "Decodes a secret key with a passphrase to obtain the private key."
  [^PGPSecretKey seckey
   ^String passphrase]
  (.extractPrivateKey seckey
    (-> (BcPGPDigestCalculatorProvider.)
        (BcPBESecretKeyDecryptorBuilder.)
        (.build (.toCharArray passphrase)))))


(defn key-info
  "Returns a map of information about the given key."
  [k]
  (when-let [^PGPPublicKey pubkey (public-key k)]
    (cond->
      {:master-key? (.isMasterKey pubkey)
       :key-id (key-id pubkey)
       :strength (.getBitStrength pubkey)
       :algorithm (key-algorithm pubkey)
       :fingerprint (hex-fingerprint pubkey)
       :encryption-key? (.isEncryptionKey pubkey)
       :user-ids (-> pubkey .getUserIDs iterator-seq vec)}

      (instance? PGPSecretKey k)
      (merge {:secret-key? true
              :signing-key? (.isSigningKey ^PGPSecretKey k)}))))
