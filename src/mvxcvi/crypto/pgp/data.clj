(ns mvxcvi.crypto.pgp.data
  "Data encryption and decryption functions.

  This namespace makes use of the concept of _encryptors_ and _decryptors_.
  These are values used to encipher and decipher data, respectively. A
  collection of encryptors may be provided to the encryption functions, and
  the any corresponding decryptor will be able to read the resulting message.

  An encryptor may be a passphrase string or a public-key object. A decryptor
  may be a passphrase string, a private-key object, or a function that accepts
  a key id and returns the corresponding private-key."
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
    java.nio.ByteBuffer
    java.security.SecureRandom
    java.util.Date
    (org.bouncycastle.bcpg
      ArmoredOutputStream)
    (org.bouncycastle.openpgp
      PGPPBEEncryptedData
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
      BcPBEDataDecryptorFactory
      BcPBEKeyEncryptionMethodGenerator
      BcPGPDigestCalculatorProvider
      BcPublicKeyDataDecryptorFactory
      BcPublicKeyKeyEncryptionMethodGenerator)))


;; ## Data Output Streams

(defn- add-encryption-method!
  "Adds an encryption method to an encrypted data generator. Returns the updated
  generator."
  [^PGPEncryptedDataGenerator generator encryptor]
  (cond
    (string? encryptor)
    (.addMethod generator
      (BcPBEKeyEncryptionMethodGenerator.
        (.toCharArray ^String encryptor)))

    (public-key encryptor)
    (.addMethod generator
      (BcPublicKeyKeyEncryptionMethodGenerator.
        (public-key encryptor)))

    :else
    (throw (IllegalArgumentException.
             (str "Don't know how to encrypt data with " (pr-str encryptor)))))
  generator)


(defn- encrypted-data-generator
  "Constructs a generator for encrypting a data packet with a symmetric session
  key. A custom random number generator may be provided. Message integrity may
  be protected by Modification Detection Code (MDC) packets."
  ^PGPEncryptedDataGenerator
  [encryptors
   {:keys [sym-algo integrity-check random]
    :or {sym-algo :aes-256
         integrity-check true}}]
  ; TODO: check for more than one passphrase encryptor?
  (reduce
    add-encryption-method!
    (PGPEncryptedDataGenerator.
      (cond->
        (BcPGPDataEncryptorBuilder.
          (tags/symmetric-key-algorithm sym-algo))
        integrity-check (.setWithIntegrityPacket true)
        random          (.setSecureRandom ^SecureRandom random)))
    (arg-coll encryptors)))


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
  [^OutputStream output encryptors & opts]
  (let [opts (arg-map opts)
        enc-gen (encrypted-data-generator encryptors opts)]
    (.open enc-gen output (byte-array (:buffer-size opts 4096)))))


(defn compressed-data-stream
  "Wraps an `OutputStream` with a compressed data generator, returning another
  stream. Typically, literal data packets will be written to this stream, which
  are compressed and written to an underlying encryption stream."
  [^OutputStream output zip-algo]
  (.open (PGPCompressedDataGenerator.
           (tags/compression-algorithm zip-algo))
         output))


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
  [^OutputStream output & opts]
  (let [{:keys [buffer-size data-type filename ^Date mtime]
         :or {buffer-size 4096
              data-type   PGPLiteralData/BINARY
              filename    PGPLiteralData/CONSOLE
              mtime       PGPLiteralData/NOW}}
        (arg-map opts)]
    (.open (PGPLiteralDataGenerator.)
           output
           (char data-type)
           (str filename)
           mtime
           (byte-array buffer-size))))



(defn armored-data-stream
  "Wraps an `OutputStream` with an armored data stream. Packets written to this
  stream will be output in ASCII encoded Base64."
  [^OutputStream output]
  (ArmoredOutputStream. output))



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
   encryptors
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
          (wrap-with encrypted-data-stream encryptors opts)
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

  See `encrypt-stream` for options."
  ^bytes
  [data encryptors & opts]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [^OutputStream stream
                (encrypt-stream buffer encryptors (arg-map opts))]
      (io/copy data stream))
    (.toByteArray buffer)))



;; ## Data Input Streams

(defprotocol DataPacket
  "Protocol for decryptable/unpackable data objects."

  (unpack-data
    [data decryptor]
    "Recursively unpacks a data packet and returns a nested sequence byte arrays
    containing the content. The decryptor is used to access encrypted packets.
    Throws an exception if encrypted data cannot be decrypted."))


(defn- read-pgp-objects
  "Decodes a sequence of PGP objects from an input stream, unpacking each
  object's data."
  [decryptor ^InputStream input]
  (let [factory (PGPObjectFactory. input)]
    (->>
      (repeatedly #(.nextObject factory))
      (take-while some?)
      (map #(unpack-data % decryptor)))))


(extend-protocol DataPacket

  PGPEncryptedDataList

  (unpack-data
    [data decryptor]
    (let [content (->> (.getEncryptedDataObjects data)
                       iterator-seq
                       (map #(unpack-data % decryptor))
                       (remove nil?)
                       first)]
      (when-not content
        (throw (IllegalArgumentException.
                 (str "Cannot decrypt " (pr-str data) " with " (pr-str decryptor)
                      " (no matching encrypted session key)"))))
      content))


  PGPPBEEncryptedData

  (unpack-data
    [data decryptor]
    (when (string? decryptor)
      (->> (BcPBEDataDecryptorFactory.
             (.toCharArray ^String decryptor)
             (BcPGPDigestCalculatorProvider.))
           (.getDataStream data)
           (read-pgp-objects decryptor))))


  PGPPublicKeyEncryptedData

  (unpack-data
    [data decryptor]
    (when-let [privkey (private-key
                         (if (ifn? decryptor)
                           (decryptor (key-id data))
                           decryptor))]
      (when (= (key-id data) (key-id privkey))
        (->> (BcPublicKeyDataDecryptorFactory. privkey)
             (.getDataStream data)
             (read-pgp-objects decryptor)))))


  PGPCompressedData

  (unpack-data
    [data decryptor]
    (->>
      (.getDataStream data)
      (read-pgp-objects decryptor)
      doall))


  PGPLiteralData

  (unpack-data
    [data decryptor]
    (bytes/to-byte-array (.getInputStream data))))



;; ## Data Decryption

(defn decrypt-stream
  "Wraps the given input stream with decryption layers. The `decryptor` should
  either be a passphrase string (to unlock PBE encrypted data), or a function
  which accepts a key-id and return the corresponding private key (to unlock
  public-key encrypted data)."
  [^InputStream input decryptor]
  (->> (PGPUtil/getDecoderStream input)
       (read-pgp-objects decryptor)
       flatten
       (map #(ByteBuffer/wrap %))
       bytes/to-input-stream))


(defn decrypt
  "Decrypts the given data source and returns an array of bytes with the
  decrypted value. See `decrypt-stream`."
  ^bytes
  [data decryptor]
  (let [buffer (ByteArrayOutputStream.)]
    (with-open [^InputStream stream
                (decrypt-stream
                  (bytes/to-input-stream data)
                  decryptor)]
      (io/copy stream buffer))
    (.toByteArray buffer)))
