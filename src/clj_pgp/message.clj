(ns clj-pgp.message
  "The functions in this namespace package raw data into PGP _messages_, which
  can be compressed, encrypted, and signed.

  The encryption functions use the concept of _encryptors_ and _decryptors_.
  A collection of encryptors may be used to encipher a message, and any
  corresponding decryptor will be able to decipher it.

  For symmetric encryption, the encryptor is the passphrase string and the
  corresponding decryptor is the same string.

  For public-key encryption, the encryptor is the public-key object and the
  decryptor is the corresponding private-key. Alternately, the decryptor can be
  a function which accepts a key id and returns the corresponding private-key,
  to look it up or unlock the key on demand."
  (:require
    [byte-streams :as bytes]
    [clojure.java.io :as io]
    (clj-pgp
      [core :as pgp]
      [tags :as tags]
      [util :refer [arg-coll arg-map]]))
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
      PGPEncryptedData
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


;; ## PGP Data Encoding

; TODO: idea - have read-message return a map with info about the message
; instead of direct byte content. For example - algorithm compressed with, ids
; of keys encrypted for, cipher encrypted with, filename, mtime, etc.

(defprotocol MessagePacket
  "Protocol for packets of message data."

  (unpack-message
    [data opts]
    "Recursively unpacks a message packet and returns a representation of the
    data. This is generally a map with subpackets in `:content`.

    See `read-message` for options."))


(defn- expand-content
  "Decodes a sequence of PGP objects from an input stream, unpacking each
  object's data."
  [^InputStream input opts]
  (->>
    (pgp/read-objects input)
    (map #(unpack-message % opts))
    flatten vec))


(defn armored-data-stream
  "Wraps an `OutputStream` with an armored data stream. Packets written to this
  stream will be output in ASCII encoded Base64."
  ^OutputStream
  [^OutputStream output]
  (ArmoredOutputStream. output))



;; ## Literal Data Packets

(def data-formats
  "Supported data formats which can be specified when building literal data
  packets."
  {:binary PGPLiteralData/BINARY
   :text   PGPLiteralData/TEXT
   :utf8   PGPLiteralData/UTF8})


(defn literal-data-stream
  "Wraps an `OutputStream` with a literal data generator, returning another
  stream. Typically, the wrapped stream is a compressed data stream or
  encrypted data stream.

  Data written to the returned stream will write a literal data packet to the
  wrapped output stream. If the data is longer than the buffer size, the packet
  is written in chunks in a streaming fashion.

  Options may be provided to customize the packet:

  - `:buffer-size` maximum number of bytes per chunk
  - `:format`      data format type
  - `:filename`    filename string for the data
  - `:mtime`       data modification time"
  ^OutputStream
  [^OutputStream output & opts]
  (let [{:keys [buffer-size format filename ^Date mtime]
         :or {buffer-size 4096
              format      :binary
              filename    PGPLiteralData/CONSOLE
              mtime       (Date.)}}
        (arg-map opts)]
    (.open (PGPLiteralDataGenerator.)
           output
           (char (data-formats format))
           (str filename)
           mtime
           (byte-array buffer-size))))


;; Read the literal data bytes from the packet.
(extend-protocol MessagePacket
  PGPLiteralData

  (unpack-message
    [packet opts]
    (let [data (bytes/to-byte-array (.getInputStream packet))
          format (tags/code->tag data-formats (char (.getFormat packet)))]
      [{:format format
        :filename (.getFileName packet)
        :mtime (.getModificationTime packet)
        :data (case format
                (:text :utf8) (String. data)
                data)}])))



;; ## Compressed Data Packets

(defn compressed-data-stream
  "Wraps an `OutputStream` with a compressed data generator, returning another
  stream. Typically, literal data packets will be written to this stream, which
  are compressed and written to an underlying encryption stream."
  ^OutputStream
  [^OutputStream output algorithm]
  (.open (PGPCompressedDataGenerator.
           (tags/compression-algorithm-code algorithm))
         output))


;; Decompress the data contained in the packet.
(extend-protocol MessagePacket
  PGPCompressedData

  (unpack-message
    [packet opts]
    (let [zip-algo (tags/compression-algorithm-tag
                     (.getAlgorithm packet))]
      (mapv #(assoc % :compress zip-algo)
            (expand-content (.getDataStream packet) opts)))))



;; ## Encrypted Data Packets

(defn- add-encryption-method!
  "Adds an encryption method to an encrypted data generator. Returns the updated
  generator."
  ^PGPEncryptedDataGenerator
  [^PGPEncryptedDataGenerator generator encryptor]
  (cond
    (string? encryptor)
    (.addMethod generator
      (BcPBEKeyEncryptionMethodGenerator.
        (.toCharArray ^String encryptor)))

    (pgp/public-key encryptor)
    (.addMethod generator
      (BcPublicKeyKeyEncryptionMethodGenerator.
        (pgp/public-key encryptor)))

    :else
    (throw (IllegalArgumentException.
             (str "Don't know how to encrypt data with " (pr-str encryptor)))))
  generator)


(defn encrypted-data-stream
  "Wraps an `OutputStream` with an encrypted data generator, returning another
  stream. The data written to the stream will be encrypted with a symmetric
  session key, which is then encrypted for each of the given public keys.

  Typically, the data written to this will consist of compressed data packets.
  If the data is longer than the buffer size, the packet is written in chunks
  in a streaming fashion.

  Options may be provided to customize the packet:

  - `:buffer-size`     maximum number of bytes per chunk
  - `:integrity-check` whether to include a Modification Detection Code packet
  - `:random`          custom random number generator"
  ^OutputStream
  [^OutputStream output cipher encryptors & opts]
  (let [encryptors (arg-coll encryptors)
        {:keys [buffer-size integrity-check random]
         :or {buffer-size 4096
              integrity-check true}}
        (arg-map opts)]
    (when (empty? (remove nil? encryptors))
      (throw (IllegalArgumentException.
               "Cannot encrypt data stream without encryptors.")))
    (when (< 1 (count (filter string? encryptors)))
      (throw (IllegalArgumentException.
               "Only one passphrase encryptor is supported")))
    (.open
      ^PGPEncryptedDataGenerator
      (reduce
        add-encryption-method!
        (PGPEncryptedDataGenerator.
          (cond->
            (BcPGPDataEncryptorBuilder.
              (tags/symmetric-key-algorithm-code cipher))
            integrity-check (.setWithIntegrityPacket true)
            random          (.setSecureRandom ^SecureRandom random)))
        encryptors)
      output
      (byte-array buffer-size))))


(extend-protocol MessagePacket

  PGPEncryptedDataList

  ;; Read through the list of encrypted session keys and attempt to find one
  ;; which the decryptor will unlock. If none are found, the message is not
  ;; decipherable and an exception is thrown.
  (unpack-message
    [packet opts]
    (let [[^PGPEncryptedData object content]
          (->> (.getEncryptedDataObjects packet)
               iterator-seq
               (map #(when-let [ds (unpack-message % opts)]
                       (vector % ds)))
               (remove nil?)
               first)]
      (when-not content
        (throw (IllegalArgumentException.
                 (str "Cannot decrypt " (pr-str packet) " with " (pr-str opts)
                      " (no matching encrypted session key)"))))
      (when (and (.isIntegrityProtected object)
                 (not (.verify object)))
        (throw (IllegalStateException.
                 (str "Encrypted data object " object
                      " failed integrity verification!"))))
      (let [mdc (.isIntegrityProtected object)]
        (mapv #(assoc % :integrity-protected? mdc) content))))


  PGPPBEEncryptedData

  ;; If the decryptor is a string, try to use it to decrypt the passphrase
  ;; protected session key.
  (unpack-message
    [packet opts]
    (let [decryptor (:decryptor opts)]
      (when (string? decryptor)
        (let [decryptor-factory (BcPBEDataDecryptorFactory.
                                  (.toCharArray ^String decryptor)
                                  (BcPGPDigestCalculatorProvider.))
              cipher (-> packet
                         (.getSymmetricAlgorithm decryptor-factory)
                         tags/symmetric-key-algorithm-tag)]
          (mapv #(assoc % :cipher cipher)
                (-> packet
                    (.getDataStream decryptor-factory)
                    (expand-content opts)))))))


  PGPPublicKeyEncryptedData

  ;; If the decryptor is callable, use it to find a private key matching the id
  ;; on the data packet. Otherwise, use it directly as a private key. If the
  ;; decryptor doesn't match the id, return nil.
  (unpack-message
    [packet opts]
    (let [decryptor (:decryptor opts)]
      (when-let [privkey (pgp/private-key
                           (if (ifn? decryptor)
                             (decryptor (pgp/key-id packet))
                             decryptor))]
        (when (= (pgp/key-id packet) (pgp/key-id privkey))
          (let [decryptor-factory (BcPublicKeyDataDecryptorFactory. privkey)
                key-id (pgp/key-id packet)
                cipher (-> packet
                           (.getSymmetricAlgorithm decryptor-factory)
                           tags/symmetric-key-algorithm-tag)]
            (mapv #(assoc % :key-id key-id :cipher cipher)
                  (-> packet
                      (.getDataStream decryptor-factory)
                      (expand-content opts)))))))))



;; ## Constructing PGP Messages

(defn message-output-stream
  "Wraps the given output stream with compression and encryption layers. The
  data will decryptable by the corresponding decryptors. Does _not_ close the
  wrapped stream when it is closed.

  Opts may contain:

  - `:buffer-size` maximum number of bytes per chunk
  - `:compress`    compress the cleartext with the given algorithm, if specified
  - `:cipher`      symmetric key algorithm to use if encryptors are provided
  - `:encryptors`  keys to encrypt the cipher session key with
  - `:armor`       whether to ascii-encode the output

  See `literal-data-stream` and `encrypted-data-stream` for more options."
  ^OutputStream
  [^OutputStream output & opts]
  (let [{:keys [compress cipher encryptors armor]
         :or {cipher :aes-256}
         :as opts}
        (arg-map opts)

        encryptors (arg-coll encryptors)

        wrap-with
        (fn [streams wrapper & args]
          (conj streams (apply wrapper (last streams) args)))

        streams
        (->
          (vector output)
          (cond->
            armor      (wrap-with armored-data-stream)
            encryptors (wrap-with encrypted-data-stream cipher encryptors opts)
            compress   (wrap-with compressed-data-stream compress))
          (wrap-with literal-data-stream opts)
          rest reverse)]
    (proxy [FilterOutputStream] [(first streams)]
      (close []
        (dorun (map #(.close ^OutputStream %) streams))))))


(defn build-message
  "Compresses, encrypts, and encodes the given data and returns an array of
  bytes containing the resulting packet. The data will decryptable by the
  corresponding decryptors.

  See `message-output-stream` for options."
  [data & opts]
  (let [opts (arg-map opts)
        buffer (ByteArrayOutputStream.)]
    (with-open [^OutputStream stream
                (message-output-stream buffer opts)]
      (io/copy data stream))
    (cond-> (.toByteArray buffer)
      (:armor opts) String.)))


(defn encrypt
  "Constructs a message packet enciphered for the given encryptors. See
  `message-output-stream` for options."
  [data encryptors & opts]
  (apply build-message data
         :encryptors encryptors
         opts))



;; ## Reading PGP Messages

(defn read-messages
  "Reads message packets from an input source and returns a sequence of message
  maps. Each message contains keys similar to the options used to build them,
  describing the type of compression used, cipher encrypted with, etc. The
  message content is stored in the `:data` entry.

  Opts may contain:

  - `:decryptor` secret to decipher the message encryption"
  [input & opts]
  (->>
    input
    bytes/to-input-stream
    PGPUtil/getDecoderStream
    pgp/read-objects
    (map #(unpack-message % (arg-map opts)))
    flatten))


(defn decrypt
  "Decrypts a message packet and attempts to decipher it with the given
  decryptor. Returns the data of the first message directly.

  See `read-messages` for options."
  [input decryptor & opts]
  (->
    (apply read-messages input
           :decryptor decryptor
           opts)
    first :data))
