(ns clj-pgp.core
  "Core functions for handling PGP objects."
  (:require
    [byte-streams :as bytes]
    [clj-pgp.error :as error]
    [clj-pgp.tags :as tags]
    [clojure.java.io :as io]
    [clojure.string :as str])
  (:import
    (java.io
      ByteArrayOutputStream
      InputStream)
    java.util.Date
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPKeyPair
      PGPObjectFactory
      PGPPrivateKey
      PGPPublicKey
      PGPPublicKeyRing
      PGPSecretKey
      PGPSignature
      PGPSignatureList
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcKeyFingerprintCalculator
      BcPBESecretKeyDecryptorBuilder
      BcPGPDigestCalculatorProvider)))


;; ## Supported Algorithms

(defmacro ^:private defalgorithms
  "Defines a set of supported tags for a type of algorithm."
  [algo-type]
  `(def ~(symbol (str algo-type "-algorithms"))
     ~(str "The set of supported " algo-type " algorithm keywords.")
     (set (keys ~(symbol "clj-pgp.tags"
                         (str algo-type "-algorithm-tags"))))))


(defalgorithms hash)
(defalgorithms compression)
(defalgorithms public-key)
(defalgorithms symmetric-key)



;; ## Public Key Coercion

(defprotocol PublicKeyContainer
  "Protocol for value types which contain or are coercible to a PGP public key."

  (public-key
    [this]
    "Coerces the argument into a PGP public key. Returns nil for other values."))


(extend-protocol PublicKeyContainer
  nil
  (public-key [_] nil)

  Object
  (public-key [_] nil)

  PGPPublicKey
  (public-key [pubkey] pubkey)

  PGPSecretKey
  (public-key [seckey] (.getPublicKey seckey))

  PGPKeyPair
  (public-key [keypair] (.getPublicKey keypair))

  PGPPublicKeyRing
  (public-key [keyring] (.getPublicKey keyring)))



;; ## Private Key Coercion

(defprotocol PrivateKeyContainer
  "Protocol for value types which contain or are coercible to a PGP private key."

  (private-key
    [this]
    "Coerces the argument into a PGP private key. Returns nil for other values."))


(extend-protocol PrivateKeyContainer
  nil
  (private-key [_] nil)

  Object
  (private-key [_] nil)

  PGPPrivateKey
  (private-key [privkey] privkey)

  PGPKeyPair
  (private-key [keypair] (.getPrivateKey keypair)))



;; ## Keypair Identifiers

(defprotocol KeyIdentifier
  "Protocol for values which can be used as PGP key identifiers."

  (key-id
    ^Long
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

(defprotocol KeyAlgorithmIdentifier
  "Protocol for values which can use or identify a cryptographic algorithm."

  (key-algorithm
    [value]
    "Returns a keyword identifying the key algorithm used by the given value."))


(extend-protocol KeyAlgorithmIdentifier
  nil
  (key-algorithm [_] nil)

  Object
  (key-algorithm [value]
    (tags/public-key-algorithm-tag value))

  PGPPublicKey
  (key-algorithm [pubkey]
    (tags/public-key-algorithm-tag
      (.getAlgorithm pubkey)))

  PGPSecretKey
  (key-algorithm [seckey]
    (tags/public-key-algorithm-tag
      (.getAlgorithm (.getPublicKey seckey))))

  PGPPrivateKey
  (key-algorithm [privkey]
    (tags/public-key-algorithm-tag
      (.getAlgorithm (.getPublicKeyPacket privkey))))

  PGPKeyPair
  (key-algorithm [keypair]
    (tags/public-key-algorithm-tag
      (.getAlgorithm (.getPublicKey keypair)))))



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
  (.extractPrivateKey
    seckey
    (-> (BcPGPDigestCalculatorProvider.)
        (BcPBESecretKeyDecryptorBuilder.)
        (.build (.toCharArray passphrase)))))



;; ## PGP Object Encoding

(defprotocol Encodable
  "Protocol for encodable PGP objects."

  (encode
    [value]
    "Encodes a PGP object into a byte array."))


(extend-protocol Encodable

  PGPPublicKey

  (encode [pubkey]
    (.getEncoded pubkey))


  PGPSignature

  (encode [sig]
    (.getEncoded sig)))


(defn encode-ascii
  "Encodes a PGP object into an ascii-armored text blob."
  [data]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [encoder (ArmoredOutputStream. buffer)]
      (io/copy (encode data) encoder))
    (str buffer)))



;; ## PGP Object Decoding

(defn read-next-object
  "A thin wrapper on reading the next object from a PGPObjectFactory."
  [^PGPObjectFactory factory]
  (.nextObject factory))


(defn ^:no-doc read-objects
  "Lazily decodes a sequence of PGP objects from an input stream."
  [^InputStream input]
  (let [factory (PGPObjectFactory. input (BcKeyFingerprintCalculator.))]
    (->> (range)
         (map (fn next-object
                [n]
                (try
                  (read-next-object factory)
                  (catch Exception e
                    (error/*handler* ::read-object-error
                                     (.getMessage e)
                                     (assoc (ex-data e) ::stream input ::nth n)
                                     e)))))
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
  (let [value (first (decode data))]
    (or (public-key value)
        (throw (IllegalStateException.
                 (str "Data did not contain a public key: " value))))))


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
