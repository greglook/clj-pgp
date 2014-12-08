(ns clj-pgp.core
  "Core functions for handling PGP objects."
  (:require
    [byte-streams :as bytes]
    [clojure.java.io :as io]
    [clojure.string :as str]
    [clj-pgp.tags :as tags])
  (:import
    (java.io
      ByteArrayOutputStream
      InputStream)
    java.util.Date
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPKeyPair
      PGPKeyRing
      PGPObjectFactory
      PGPPrivateKey
      PGPPublicKey
      PGPPublicKeyEncryptedData
      PGPSecretKey
      PGPSignature
      PGPSignatureList
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyDecryptorBuilder
      BcPGPDigestCalculatorProvider)))


;; ## Supported Algorithms

(defmacro ^:private defalgorithms
  "Defines a set of supported tags for a type of algorithm."
  [algo-type]
  `(def ~(symbol (str algo-type "-algorithms"))
     ~(str "The set of supported " algo-type " algorithm tags. Each value is "
           "a keyword which can be mapped to a numeric code by `clj-pgp.tags/"
           algo-type "-algorithm`.")
     (set (keys ~(symbol "clj-pgp.tags"
                         (str algo-type "-algorithm-tags"))))))


(defalgorithms hash)
(defalgorithms compression)
(defalgorithms public-key)
(defalgorithms symmetric-key)



;; ## Public Key Coercion

(defmulti public-key
  "Coerces the argument into a PGP public key. Returns nil for other values."
  class)

(defmethod public-key :default [_] nil)

(defmethod public-key PGPPublicKey
  [^PGPPublicKey pubkey]
  pubkey)

(defmethod public-key PGPSecretKey
  [^PGPSecretKey seckey]
  (.getPublicKey seckey))

(defmethod public-key PGPKeyPair
  [^PGPKeyPair keypair]
  (.getPublicKey keypair))



;; ## Private Key Coercion

(defmulti private-key
  "Coerces the argument into a PGP private key. Returns nil for other values."
  class)

(defmethod private-key :default [_] nil)

(defmethod private-key PGPPrivateKey
  [^PGPPrivateKey privkey]
  privkey)

(defmethod private-key PGPKeyPair
  [^PGPKeyPair keypair]
  (.getPrivateKey keypair))



;; ## Keypair Identifiers

(defprotocol KeyIdentifier
  "Protocol for values which can be used as PGP key identifiers."

  (key-id
    [value]
    "Returns the numeric PGP key identifier for the given value."))


(extend-protocol KeyIdentifier
  nil           (key-id [_] nil)
  Long          (key-id [id] id)
  String        (key-id [hex] (.longValue (BigInteger. hex 16)))
  PGPPublicKey  (key-id [pubkey]  (.getKeyID pubkey))
  PGPSecretKey  (key-id [seckey]  (.getKeyID seckey))
  PGPPrivateKey (key-id [privkey] (.getKeyID privkey))
  PGPKeyPair    (key-id [keypair] (.getKeyID keypair))
  PGPSignature  (key-id [sig]     (.getKeyID sig)))


(defn hex-id
  "Returns the PGP key identifier for the given value as a hexadecimal string."
  [value]
  (when value
    (format "%016x" (key-id value))))


(defn hex-fingerprint
  "Returns the PGP key fingerprint as a hexadecimal string."
  [value]
  (when-let [^PGPPublicKey pubkey (public-key value)]
    (->> (.getFingerprint pubkey)
         (map (partial format "%02X"))
         str/join)))



;; ## Keypair Algorithms

(defmulti key-algorithm
  "Returns a keyword identifying the public-key algorithm used by the given
  value."
  class)

(defmethod key-algorithm nil [_] nil)

(defmethod key-algorithm clojure.lang.Keyword
  [algorithm]
  (when-not (contains? public-key-algorithms algorithm)
    (throw (IllegalArgumentException.
             (str "Invalid public-key-algorithm name " algorithm))))
  algorithm)

(defmethod key-algorithm Number
  [code]
  (tags/public-key-algorithm-tag code))

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

(defn key-info
  "Returns a map of information about the given key."
  [k]
  (when-let [^PGPPublicKey pubkey (public-key k)]
    (cond->
      {:master-key? (.isMasterKey pubkey)
       :key-id (hex-id pubkey)
       :strength (.getBitStrength pubkey)
       :algorithm (key-algorithm pubkey)
       :fingerprint (hex-fingerprint pubkey)
       :created-at (.getCreationTime pubkey)
       :revoked? (.isRevoked pubkey)
       :encryption-key? (.isEncryptionKey pubkey)
       :user-ids (-> pubkey .getUserIDs iterator-seq vec)}

      (pos? (.getValidSeconds pubkey))
      (assoc :expires-at (Date. (+ (.getTime (.getCreationTime pubkey))
                                   (* 1000 (.getValidSeconds pubkey)))))

      (instance? PGPSecretKey k)
      (merge {:secret-key? true
              :signing-key? (.isSigningKey ^PGPSecretKey k)}))))


(defn unlock-key
  "Decodes a secret key with a passphrase to obtain the private key."
  [^PGPSecretKey seckey
   ^String passphrase]
  (.extractPrivateKey seckey
    (-> (BcPGPDigestCalculatorProvider.)
        (BcPBESecretKeyDecryptorBuilder.)
        (.build (.toCharArray passphrase)))))



;; ## PGP Object Encoding

(defmulti encode
  "Encodes a PGP object into a byte array."
  class)

(defmethod encode PGPPublicKey
  [^PGPPublicKey pubkey]
  (.getEncoded pubkey))

(defmethod encode PGPPrivateKey
  [^PGPPrivateKey privkey]
  (.getEncoded (.getPrivateKeyDataPacket privkey)))

(defmethod encode PGPSignature
  [^PGPSignature sig]
  (.getEncoded sig))


(defn encode-ascii
  "Encodes a PGP object into an ascii-armored text blob."
  [data]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [encoder (ArmoredOutputStream. buffer)]
      (io/copy (encode data) encoder))
    (str buffer)))



;; ## PGP Object Decoding

(defn ^:no-doc read-objects
  "Lazily decodes a sequence of PGP objects from an input stream."
  [^InputStream input]
  (let [factory (PGPObjectFactory. input)]
    (->>
      (repeatedly #(.nextObject factory))
      (take-while some?))))


(defn decode
  "Decodes PGP objects from an encoded data source. Returns a sequence of
  decoded objects."
  [data]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream data))]
    (doall (read-objects stream))))


(defn decode-public-key
  "Decodes a public key from the given data. Throws an exception if the data
  does not contain a public key value."
  [data]
  (when-let [pubkey (first (decode data))]
    (when-not (instance? PGPPublicKey pubkey)
      (throw (IllegalStateException.
               (str "Data did not contain a public key: " pubkey))))
    pubkey))


(defn decode-signatures
  "Decodes a sequence of signatures from the given data. Throws an exception if
  the data does not contain a signature list."
  [data]
  (->>
    (decode data)
    (map
      (fn [object]
        (condp instance? object
          PGPSignature
          object

          PGPSignatureList
          (map #(.get ^PGPSignatureList object %)
               (range (.size ^PGPSignatureList object))))))
    flatten))
