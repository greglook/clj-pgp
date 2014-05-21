(ns mvxcvi.crypto.pgp.codec
  (:require
    byte-streams
    [clojure.java.io :as io]
    (mvxcvi.crypto.pgp
      [key :refer [key-info public-key]]))
  (:import
    (java.io
      ByteArrayOutputStream)
    (org.bouncycastle.bcpg
      ArmoredOutputStream
      BCPGOutputStream)
    (org.bouncycastle.openpgp
      PGPObjectFactory
      PGPPublicKey
      PGPSecretKey
      PGPSignature
      PGPSignatureList
      PGPUtil)))


;; PRINT METHODS

(defmethod print-method PGPPublicKey
  [k ^java.io.Writer w]
  (.write w (str "#<PGPPublicKey " (key-info k) ">")))


(defmethod print-method PGPSecretKey
  [k ^java.io.Writer w]
  (.write w (str "#<PGPSecretKey " (key-info k) ">")))



;; ENCODING

(defmulti encode
  "Encodes a PGP object into a byte sequence."
  class)

(defmethod encode PGPPublicKey
  [^PGPPublicKey pubkey]
  (.getEncoded pubkey))

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



;; DECODING

(defn decode
  "Decodes PGP objects from an encoded data source. Returns a sequence of PGP
  objects."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (byte-streams/to-input-stream source))]
    (let [factory (PGPObjectFactory. stream)]
      (->> (repeatedly #(.nextObject factory))
           (take-while identity)
           doall))))


(defn decode-public-key
  "Decodes a public key from the given data."
  [source]
  (-> source decode first public-key))


(defn decode-signature
  [source]
  (let [^PGPSignatureList sigs (first (decode source))]
    (when-not (instance? PGPSignatureList sigs)
      (throw (IllegalArgumentException.
               (str "Data did not contain a PGPSignatureList: " sigs))))
    (when-not (.isEmpty sigs)
      (.get sigs 0))))
