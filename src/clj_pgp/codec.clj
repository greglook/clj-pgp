(ns clj-pgp.codec
  "Functions for encoding and decoding PGP objects."
  (:require
    [byte-streams :as bytes]
    [clojure.java.io :as io]
    [clj-pgp.core :refer [hex-id]])
  (:import
    (java.io
      ByteArrayOutputStream)
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPKeyPair
      PGPObjectFactory
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey
      PGPSignature
      PGPSignatureList
      PGPUtil)))


;; ## Print Methods

(defmethod print-method PGPPublicKey
  [k ^java.io.Writer w]
  (.write w (str "#<PGPPublicKey " (hex-id k) ">")))

(defmethod print-method PGPPrivateKey
  [k ^java.io.Writer w]
  (.write w (str "#<PGPPrivateKey " (hex-id k) ">")))

(defmethod print-method PGPSecretKey
  [k ^java.io.Writer w]
  (.write w (str "#<PGPSecretKey " (hex-id k) ">")))

(defmethod print-method PGPKeyPair
  [k ^java.io.Writer w]
  (.write w (str "#<PGPKeyPair " (hex-id k) ">")))



;; ## Encoding

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



;; ## Decoding

(defn decode
  "Decodes PGP objects from an encoded data source. Returns a sequence of
  decoded objects."
  [data]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream data))]
    (let [factory (PGPObjectFactory. stream)]
      (->> (repeatedly #(.nextObject factory))
           (take-while some?)
           doall))))


(defn decode-public-key
  "Decodes a public key from the given data."
  [data]
  (when-let [pubkey (first (decode data))]
    (when-not (instance? PGPPublicKey pubkey)
      (throw (IllegalStateException.
               (str "Data did not contain a public key: " pubkey))))
    pubkey))


(defn decode-signature
  "Decodes a single signature from an encoded signature list."
  [data]
  (let [^PGPSignatureList sigs (first (decode data))]
    (when-not (instance? PGPSignatureList sigs)
      (throw (IllegalArgumentException.
               (str "Data did not contain a PGPSignatureList: " sigs))))
    (when-not (.isEmpty sigs)
      (.get sigs 0))))
