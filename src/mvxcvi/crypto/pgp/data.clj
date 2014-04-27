(ns mvxcvi.crypto.pgp.data
  (:require
    [clojure.java.io :as io]
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [key :refer [public-key]]
      [tags :as tags]
      [util :refer [hex-str]]))
  (:import
    (java.io
      ByteArrayOutputStream
      FilterOutputStream
      InputStream
      OutputStream)
    (java.security
      SecureRandom)
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPCompressedDataGenerator
      PGPEncryptedDataGenerator
      PGPPrivateKey)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPDataEncryptorBuilder
      BcPGPDigestCalculatorProvider
      BcPublicKeyKeyEncryptionMethodGenerator)))


;; DATA ENCRYPTION

(defn- encrypted-data-generator
  ^PGPEncryptedDataGenerator
  [algorithm pubkey]
  (-> algorithm
      BcPGPDataEncryptorBuilder.
      (.setSecureRandom (SecureRandom.))
      PGPEncryptedDataGenerator.
      (doto (.addMethod (BcPublicKeyKeyEncryptionMethodGenerator. (public-key pubkey))))))


(defn encrypt-stream
  "Wraps the given output stream with encryption layers. The data will be
  encrypted with a symmetric algorithm, whose key will be encrypted by the
  given PGP public key.

  Opts may contain:
  - :algorithm    symmetric key algorithm to use
  - :compress     if specified, compress the cleartext with the given algorithm
  - :armor        whether to ascii-encode the output"
  ^OutputStream
  [^OutputStream output
   pubkey
   opts]
  (let [wrap-stream
        (fn [streams wrapper]
          (conj streams (wrapper (last streams))))

        streams
        (->
          (vector output)
          (cond->
            (:armor opts)
            (wrap-stream
              #(ArmoredOutputStream. %))
            (:compress opts)
            (wrap-stream
              #(-> (:compress opts)
                   PGPCompressedDataGenerator.
                   (.open %))))
          (wrap-stream
            #(-> (:algorithm opts :sha1)
                 (encrypted-data-generator pubkey)
                 (.open ^OutputStream % 1024)))
          rest reverse)]
    (proxy [FilterOutputStream] [(first streams)]
      (close []
        (->> streams (map #(.close ^OutputStream %)) dorun)))))


(defn encrypt
  "Encrypts the given data source and returns an array of bytes with the
  encrypted value. Opts are as in encrypt-stream."
  ([data pubkey]
   (encrypt data pubkey nil))
  ([data pubkey opt-key opt-val & opts]
   (encrypt data pubkey (assoc opts opt-key opt-val)))
  ([data pubkey opts]
   (let [buffer (ByteArrayOutputStream.)]
     (with-open [stream (encrypt-stream buffer pubkey opts)]
       (io/copy data stream))
     (.toByteArray buffer))))



;; DATA DECRYPTION

(defn decrypt-stream
  [^InputStream input
   privkey]
  nil)


(defn decrypt
  [data privkey]
  nil)
