(ns mvxcvi.crypto.pgp.data
  "Data encryption and decryption functions."
  (:require
    [byte-streams :as bytes]
    [clojure.java.io :as io]
    (mvxcvi.crypto.pgp
      [tags :as tags]
      [util :refer [key-id public-key private-key arg-coll arg-map]]))
  (:import
    (java.io
      ByteArrayOutputStream
      FilterOutputStream
      InputStream
      OutputStream)
    java.security.SecureRandom
    java.util.Date
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPCompressedData
      PGPCompressedDataGenerator
      PGPEncryptedDataGenerator
      PGPEncryptedDataList
      PGPLiteralData
      PGPLiteralDataGenerator
      PGPObjectFactory
      PGPPublicKeyEncryptedData
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPDataEncryptorBuilder
      BcPublicKeyDataDecryptorFactory
      BcPublicKeyKeyEncryptionMethodGenerator)))


;; ## Utility Functions

(defn- read-pgp-objects
  "Decodes a lazy sequence of PGP objects from an input stream."
  [^InputStream input]
  (let [factory (PGPObjectFactory. input)]
    (take-while some? (repeatedly #(.nextObject factory)))))



;; ## Armor ASCII Encoding

(defn armored-data-stream
  "Wraps an `OutputStream` with an armored data stream. Packets written to this
  stream will be output in ASCII encoded Base64."
  [^OutputStream stream]
  (ArmoredOutputStream. stream))


(defn armor-data-packet
  "Builds an armored data packet containing the given data. Returns a byte
  array containing the ASCII-encoded packet."
  ^bytes
  [data]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [armor-out (ArmoredOutputStream. buffer)]
      (bytes/transfer data armor-out))
    (.toByteArray buffer)))



;; ## Literal Data Packets

(defn literal-data-stream
  "Wraps an `OutputStream` with a literal data generator, returning another
  stream. Typically, the wrapped stream is a compressed data stream or
  encrypted data stream.

  Data written to the returned stream will write a literal data packet to the
  wrapped output stream. If the data is longer than the buffer size, the packet
  is written in chunks in a streaming fashion.

  Options may be provided to customize the packet:

  - `:buffer-size` maximum number of bytes per chunk
  - `:data-type` PGP document type, binary by default
  - `:filename` string giving the 'filename' of the data
  - `:mtime` modification time of the packet contents, defaults to the current time"
  [^OutputStream stream & opts]
  (let [{:keys [data-type filename ^Date mtime buffer-size]
         :or {buffer-size 4096
              data-type   PGPLiteralData/BINARY
              filename    PGPLiteralData/CONSOLE
              mtime       PGPLiteralData/NOW}}
        (arg-map opts)]
    (.open (PGPLiteralDataGenerator.)
           stream
           (char data-type)
           (str filename)
           mtime
           (byte-array buffer-size))))


(defn literal-data-packet
  "Builds a literal data packet containing the given data. Returns a byte array
  containing the encoded packet.

  This function buffers the data in memory and writes out a single content
  packet.

  Options may be provided to customize the packet:

  - `:data-type` sets the PGP document type - binary by default
  - `:filename` a string giving the 'filename' of the data
  - `:mtime` modification time of the packet contents - defaults to the current time"
  ^bytes
  [data & opts]
  (let [{:keys [data-type filename ^Date mtime]
         :or {data-type PGPLiteralData/BINARY
              filename  PGPLiteralData/CONSOLE
              mtime     PGPLiteralData/NOW}}
        (arg-map opts)
        data-bytes (bytes/to-byte-array data)
        buffer (ByteArrayOutputStream.)]
    (with-open [packet-out (.open (PGPLiteralDataGenerator.)
                                  buffer
                                  (char data-type)
                                  (str filename)
                                  (long (count data-bytes))
                                  mtime)]
      (io/copy data-bytes packet-out))
    (.toByteArray buffer)))



;; ## Compressed Data Packets

(defn compressed-data-stream
  "Wraps an `OutputStream` with a compressed data generator, returning another
  stream. Typically, literal data packets will be written to this stream, which
  are compressed and written to an underlying encryption stream."
  [^OutputStream stream zip-algo]
  (.open (PGPCompressedDataGenerator.
           (tags/compression-algorithm zip-algo))
         stream))


(defn compress-data-packet
  "Builds a compressed data packet containing the given data. Returns a byte
  array containing the compressed packet. Typically, the input consists of
  literal data packets.

  This function buffers the data in memory and writes out a single compressed
  packet."
  ^bytes
  [data zip-algo]
  (let [data-bytes (bytes/to-byte-array data)
        buffer (ByteArrayOutputStream.)]
    (with-open [packet-out ^OutputStream (compressed-data-stream buffer zip-algo)]
      (io/copy data-bytes packet-out))
    (.toByteArray buffer)))



;; ## Encrypted Data Packets

(defn- encrypted-data-generator
  "Constructs a generator for encrypting a data packet with a symmetric session
  key. A custom random number generator may be provided. Message integrity may
  be protected by Modification Detection Code (MDC) packets."
  ^PGPEncryptedDataGenerator
  [pubkeys
   {:keys [sym-algo integrity-check random]
    :or {sym-algo :aes-256
         integrity-check true}}]
  (let [enc-gen (PGPEncryptedDataGenerator.
                  (cond->
                    (BcPGPDataEncryptorBuilder.
                      (tags/symmetric-key-algorithm sym-algo))
                    integrity-check (.setWithIntegrityPacket true)
                    random          (.setSecureRandom ^SecureRandom random)))]
    (doseq [pubkey (arg-coll pubkeys)]
      (.addMethod enc-gen (BcPublicKeyKeyEncryptionMethodGenerator. (public-key pubkey))))
    enc-gen))


(defn encrypted-data-stream
  "Wraps an `OutputStream` with an encrypted data generator, returning another
  stream. The data written to the stream will be encrypted with a symmetric
  session key, which is then encrypted for each of the given public keys.

  Typically, the data written to this will consist of compressed data packets.
  If the data is longer than the buffer size, the packet is written in chunks
  in a streaming fashion.

  Options may be provided to customize the packet:

  - `:buffer-size` maximum number of bytes per chunk
  - `:sym-algo` symmetric encryption algorithm to use for session key
  - `:integrity-check` whether to include a Modification Detection Code packet
  - `:random` custom random number generator"
  [^OutputStream stream pubkeys & opts]
  (let [opts (arg-map opts)
        enc-gen (encrypted-data-generator pubkeys opts)]
    (.open enc-gen stream (byte-array (:buffer-size opts 4096)))))


(defn encrypt-data-packet
  "Builds an encrypted data packet containing the given data. Returns a byte
  array containing the encoded packet. Typically, the input consists of
  literal or compressed data packets.

  Options may be provided to customize the packet:

  - `:sym-algo` symmetric encryption algorithm to use for session key
  - `:integrity-check` whether to include a Modification Detection Code packet
  - `:random` custom random number generator"
  ^bytes
  [data pubkeys & opts]
  (let [opts (arg-map opts)
        data-bytes (bytes/to-byte-array data)
        buffer (ByteArrayOutputStream.)
        enc-gen (encrypted-data-generator pubkeys opts)]
    (with-open [packet-out (.open enc-gen buffer (long (count data-bytes)))]
      (io/copy data-bytes packet-out))
    (.toByteArray buffer)))



;; ## Data Encryption

(defn encrypt-stream
  "Wraps the given output stream with encryption and compression layers. The
  data will decryptable by the owners of the given PGP public key(s).

  Opts may contain:

  - `:buffer-size` maximum number of bytes per chunk
  - `:zip-algo`    if specified, compress the cleartext with the given algorithm
  - `:sym-algo`    symmetric key algorithm to use
  - `:armor`       whether to ascii-encode the output

  See `literal-data-stream` and `encrypted-data-stream` for more options."
  [^OutputStream output
   pubkeys
   & opts]
  (let [{:keys [zip-algo armor] :as opts} (arg-map opts)

        wrap-with
        (fn [streams wrapper & args]
          (conj streams (apply wrapper (last streams) args)))

        streams
        (->
          (vector output)
          (cond-> armor
            (wrap-with armored-data-stream))
          (wrap-with encrypted-data-stream pubkeys opts)
          (cond-> zip-algo
            (wrap-with compressed-data-stream zip-algo))
          (wrap-with literal-data-stream opts)
          rest reverse)]
    (proxy [FilterOutputStream] [(first streams)]
      (close []
        (dorun (map #(.close ^OutputStream %) streams))))))


(defn encrypt
  "Compresses, encrypts, and encodes the given data and returns an array of
  bytes containing the resulting packet. The data will decryptable by the
  owners of the given PGP public key(s).

  Opts may contain:

  - `:zip-algo` if specified, compress the cleartext with the given algorithm
  - `:sym-algo` symmetric key algorithm to use
  - `:armor`    whether to ascii-encode the output

  See `literal-data-packet` and `encrypt-data-packet` for more options."
  ^bytes
  [data pubkeys & opts]
  (let [{:keys [zip-algo armor] :as opts} (arg-map opts)]
    (-> data
        (literal-data-packet opts)
        (cond-> zip-algo
          (compress-data-packet zip-algo))
        (encrypt-data-packet pubkeys opts)
        (cond-> armor
          (armor-data-packet)))))



;; ## Data Decryption

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
  (->>
    data-list
    (map (juxt identity (comp get-privkey key-id)))
    (filter second)
    first))


(defn decrypt-stream
  "Wraps the given input stream with decryption layers. The get-privkey
  function should accept a key-id and return the corresponding unlocked private
  key, or nil if such a key is not available."
  ^InputStream
  [^InputStream input
   get-privkey]
  (when-let [[^PGPPublicKeyEncryptedData encrypted-data privkey]
             (-> input
                 read-encrypted-data
                 (find-data get-privkey))]
    (->
      encrypted-data
      (.getDataStream (BcPublicKeyDataDecryptorFactory. (private-key privkey)))
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
                         (bytes/to-input-stream data)
                         get-privkey)]
      (io/copy stream buffer))
    (.toByteArray buffer)))
