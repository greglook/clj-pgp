(ns mvxcvi.crypto.pgp.key
  "Key-related functions."
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


;; ## Key Identity Coercion

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



;; ## Key Algorithm Coercion

(defmulti key-algorithm
  "Returns a keyword identifying the PGP key algorithm used by the given value."
  class)

(defmethod key-algorithm nil [_] nil)

; TODO: this should validate the keyword.
(defmethod key-algorithm clojure.lang.Keyword [kw] kw)

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



;; ## Public Key Coercion

(defmulti public-key
  "Determines the public PGP key associated with the argument."
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



;; ## Key Utilities

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
       :fingerprint (->> (.getFingerprint pubkey)
                         (map (partial format "%02X"))
                         str/join)
       :encryption-key? (.isEncryptionKey pubkey)
       :user-ids (-> pubkey .getUserIDs iterator-seq vec)}

      (instance? PGPSecretKey k)
      (merge {:secret-key? true
              :signing-key? (.isSigningKey ^PGPSecretKey k)}))))
