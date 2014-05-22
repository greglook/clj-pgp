(ns mvxcvi.crypto.pgp.key
  (:require
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [tags :as tags]
      [util :refer [hex-str]]))
  (:import
    (org.bouncycastle.openpgp
      PGPEncryptedData
      PGPKeyRing
      PGPPrivateKey
      PGPPublicKey
      PGPPublicKeyRingCollection
      PGPSecretKey
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPSignature)
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyDecryptorBuilder
      BcPGPDigestCalculatorProvider)))


;; PUBLIC KEY COERCION

(defmulti public-key
  "Determines the public PGP key associated with the argument."
  class)

(defmethod public-key PGPPublicKey
  [^PGPPublicKey pubkey]
  pubkey)

(defmethod public-key PGPSecretKey
  [^PGPSecretKey seckey]
  (.getPublicKey seckey))

(defmethod public-key PGPKeyRing
  [^PGPKeyRing keyring]
  (.getPublicKey keyring))

(defmethod public-key PGPPublicKeyRingCollection
  [^PGPPublicKeyRingCollection pubring]
  (-> pubring .getKeyRings iterator-seq first public-key))

(defmethod public-key PGPSecretKeyRingCollection
  [^PGPSecretKeyRingCollection secring]
  (-> secring .getKeyRings iterator-seq first public-key))



;; SECRET KEY COERCION

(defmulti secret-key
  "Determines the secret PGP key associated with the argument."
  class)

(defmethod secret-key PGPSecretKey
  [^PGPSecretKey seckey]
  seckey)

(defmethod secret-key PGPSecretKeyRing
  [^PGPSecretKeyRing secring]
  (.getSecretKey secring))

(defmethod secret-key PGPSecretKeyRingCollection
  [^PGPSecretKeyRingCollection secring]
  (-> secring .getKeyRings iterator-seq first secret-key))



;; KEY IDENTITY COERCION

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

(defmethod key-id PGPPrivateKey
  [^PGPPrivateKey privkey]
  (.getKeyID privkey))

(defmethod key-id PGPSignature
  [^PGPSignature sig]
  (.getKeyID sig))

(defmethod key-id PGPEncryptedData
  [^PGPEncryptedData data]
  (.getKeyID data))



;; KEY ALGORITHM COERCION

(defmulti key-algorithm
  "Returns a keyword identifying the PGP key algorithm used by the given value."
  class)

(defmethod key-algorithm nil [_] nil)

(defmethod key-algorithm clojure.lang.Keyword [kw] kw)

(defmethod key-algorithm Number
  [code]
  (tags/lookup tags/public-key-algorithms code))

(defmethod key-algorithm PGPPublicKey
  [^PGPPublicKey pubkey]
  (key-algorithm (.getAlgorithm pubkey)))

(defmethod key-algorithm PGPSecretKey
  [^PGPSecretKey seckey]
  (key-algorithm (public-key seckey)))

(defmethod key-algorithm PGPPrivateKey
  [^PGPPrivateKey privkey]
  (key-algorithm (.getAlgorithm (.getPublicKeyPacket privkey))))



;; KEY UTILITIES

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
  (when-let [pubkey (public-key k)]
    (cond->
      {:master-key? (.isMasterKey pubkey)
       :key-id (hex-str (key-id pubkey))
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
