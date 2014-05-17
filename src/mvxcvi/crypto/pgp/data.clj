(ns mvxcvi.crypto.pgp.data
  (:require
    byte-streams
    [clojure.java.io :as io]
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [key :as k]
      [tags :as tags]
      [util :refer [hex-str read-pgp-objects]]))
  (:import
    (java.io
      ByteArrayOutputStream
      FilterOutputStream
      InputStream
      OutputStream)
    (java.security
      SecureRandom)
    (java.util
      Date)
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPCompressedData
      PGPCompressedDataGenerator
      PGPEncryptedData
      PGPEncryptedDataGenerator
      PGPEncryptedDataList
      PGPLiteralData
      PGPLiteralDataGenerator
      PGPObjectFactory
      PGPPrivateKey
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPDataEncryptorBuilder
      BcPGPDigestCalculatorProvider
      BcPublicKeyDataDecryptorFactory
      BcPublicKeyKeyEncryptionMethodGenerator)))


;; DATA ENCRYPTION

(defn- literal-data-generator
  ^OutputStream
  [^OutputStream stream filename]
  (.open (PGPLiteralDataGenerator.)
    stream
    PGPLiteralData/BINARY
    filename
    PGPLiteralData/NOW
    (byte-array 1024)))


(defn- compressed-data-generator
  ^OutputStream
  [^OutputStream stream algorithm]
  (-> algorithm
      tags/compression-algorithm
      PGPCompressedDataGenerator.
      (.open stream)))


(defn- encrypted-data-generator
  ^OutputStream
  [^OutputStream stream algorithm pubkey]
  (-> algorithm
      tags/symmetric-key-algorithm
      BcPGPDataEncryptorBuilder.
      (.setSecureRandom (SecureRandom.))
      PGPEncryptedDataGenerator.
      (doto (.addMethod (BcPublicKeyKeyEncryptionMethodGenerator. (k/public-key pubkey))))
      (.open stream (byte-array 1024))))


(defn encrypt-stream
  "Wraps the given output stream with encryption layers. The data will be
  encrypted with a symmetric algorithm, whose key will be encrypted by the
  given PGP public key.

  Opts may contain:
  - :algorithm    symmetric key algorithm to use
  - :compress     if specified, compress the cleartext with the given algorithm
  - :armor        whether to ascii-encode the output
  - :filename     optional name to give to the literal data packet"
  ^OutputStream
  [^OutputStream output
   pubkey
   opts]
  (let [wrap-stream
        (fn [streams wrapper & args]
          (conj streams (apply wrapper (last streams) args)))

        streams
        (->
          (vector output)
          (cond->
            (:armor opts)
            (wrap-stream
              #(ArmoredOutputStream. %)))
          (wrap-stream
            encrypted-data-generator
            (:algorithm opts :aes-256)
            pubkey)
          (cond->
            (:compress opts)
            (wrap-stream
              compressed-data-generator
              (:compress opts)))
          (wrap-stream
            literal-data-generator
            (:filename opts ""))
          rest reverse)]
    (proxy [FilterOutputStream] [(first streams)]
      (close []
        (dorun (map #(.close ^OutputStream %) streams))))))


(defn encrypt
  "Encrypts the given data source and returns an array of bytes with the
  encrypted value. Opts are as in encrypt-stream."
  ([data pubkey]
   (encrypt data pubkey nil))
  ([data pubkey opt-key opt-val & opts]
   (encrypt data pubkey
            (assoc (apply hash-map opts)
                   opt-key opt-val)))
  ([data pubkey opts]
   (let [buffer (ByteArrayOutputStream.)]
     (with-open [stream (encrypt-stream buffer pubkey opts)]
       (io/copy (byte-streams/to-input-stream data) stream))
     (.toByteArray buffer))))



;; DATA DECRYPTION

(defn- read-encrypted-data
  "Reads a raw input stream to decode a PGPEncryptedDataList. Returns a sequence
  of encrypted data objects."
  [^InputStream input]
  (when-let [object (-> input PGPUtil/getDecoderStream read-pgp-objects first)]
    (when-not (instance? PGPEncryptedDataList object)
      (throw (IllegalStateException.
               (str "PGP object stream did not contain an encrypted data list:"
                    object))))
    (iterator-seq (.getEncryptedDataObjects ^PGPEncryptedDataList object))))


(defn- find-data
  "Finds which of the encrypted data objects in the given list is decryptable
  by a local private key. Returns a vector of the encrypted data and the
  corresponding private key."
  [data-list get-privkey]
  (some #(when-let [privkey (get-privkey (k/key-id %))]
           [% privkey])
        data-list))


(defn decrypt-stream
  "Wraps the given input stream with decryption layers. The get-privkey
  function should accept a key-id and return the corresponding unlocked private
  key, or nil if such a key is not available."
  ^InputStream
  [^InputStream input
   get-privkey]
  (when-let [[encrypted-data privkey]
             (-> input
                 read-encrypted-data
                 (find-data get-privkey))]
    (->
      encrypted-data
      (.getDataStream (BcPublicKeyDataDecryptorFactory. privkey))
      read-pgp-objects
      first
      (as-> object
        (if (instance? PGPCompressedData object)
          (-> ^PGPCompressedData object .getDataStream read-pgp-objects first)
          object)
        (if (instance? PGPLiteralData object)
          (.getInputStream ^PGPLiteralData object)
          (throw (IllegalArgumentException.
                   "Encrypted PGP data did not contain a literal data packet.")))))))


(defn decrypt
  "Decrypts the given data source and returns an array of bytes with the
  decrypted value."
  [data get-privkey]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [stream (decrypt-stream
                         (byte-streams/to-input-stream data)
                         get-privkey)]
      (io/copy stream buffer))
    (.toByteArray buffer)))
