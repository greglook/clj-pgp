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
    [clj-pgp.core :as pgp]
    [clj-pgp.tags :as tags]
    [clj-pgp.util :refer [arg-coll arg-map]]
    [clojure.java.io :as io])
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
      PGPEncryptedData
      PGPEncryptedDataGenerator
      PGPEncryptedDataList
      PGPLiteralData
      PGPLiteralDataGenerator
      PGPMarker
      PGPPBEEncryptedData
      PGPPublicKeyEncryptedData
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcPBEDataDecryptorFactory
      BcPBEKeyEncryptionMethodGenerator
      BcPGPDataEncryptorBuilder
      BcPGPDigestCalculatorProvider
      BcPublicKeyDataDecryptorFactory
      BcPublicKeyKeyEncryptionMethodGenerator)))


;; ## Helpers

(defn- with-reduce-attrs
  "Creates a new reducing function that merges the kvs onto the value passed
  to the `rf`"
  [rf & kvs]
  (fn reducer
    [acc value]
    (rf acc (apply assoc value kvs))))



;; ## PGP Data Encoding

(defprotocol ^:no-doc MessagePacket
  "Protocol for packets of message data."

  (reduce-message
    [data opts rf acc]
    "Recursively unpacks a message packet and calls `rf` with `acc` and the message as map.
    See `reduce-messages` for the map structure and options")

  (readable
    [data opts]
    "Determines if the message packet can be read using the given options. Should return the
    readable object itself if it's readable or nil if not."))


(defn- reduce-content
  "Decodes a sequence of PGP objects from an input stream, unpacking each
  objects data.
  See `reduce-messages` for options"
  [^InputStream input opts rf acc]
  (reduce
    #(reduce-message %2 opts rf %1)
    acc
    (pgp/read-objects input)))


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

  (reduce-message
    [packet opts rf acc]
    (let [data (.getInputStream packet)
          format (tags/code->tag data-formats (char (.getFormat packet)))]
      (rf acc {:format format
               :filename (.getFileName packet)
               :mtime (.getModificationTime packet)
               :data data})))

  (readable
    [packet opts]
    ;; PGPLiteralData is always readable
    packet)


  PGPMarker

  (reduce-message
    [packet opts rf acc]
    ;; Such a packet MUST be ignored when received. It may be placed at the
    ;; beginning of a message that uses features not available in PGP 2.6.x
    ;; in order to cause that version to report that newer software is
    ;; necessary to process the message.
    acc)

  (readable
    [packet opts]
    ;; PGPMarker is always readable
    packet))



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

  (reduce-message
    [packet opts rf acc]
    (let [zip-algo (tags/compression-algorithm-tag
                     (.getAlgorithm packet))]
      (reduce
        (fn [acc packet]
          (reduce-message packet opts (with-reduce-attrs rf :compress zip-algo) acc))
        acc
        (pgp/read-objects (.getDataStream packet)))))

  (readable
    [packet opts]
    ;; PGPCompressedData is always readable
    packet))



;; ## Encrypted Data Packets

(defn- add-encryption-method!
  "Adds an encryption method to an encrypted data generator. Returns the updated
  generator."
  ^PGPEncryptedDataGenerator
  [^PGPEncryptedDataGenerator generator encryptor]
  (cond
    (string? encryptor)
    (.addMethod
      generator
      (BcPBEKeyEncryptionMethodGenerator.
        (.toCharArray ^String encryptor)))

    (pgp/public-key encryptor)
    (.addMethod
      generator
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

  - `:buffer-size`      maximum number of bytes per chunk
  - `:integrity-packet` whether to include a Modification Detection Code packet
  - `:random`           custom random number generator"
  ^OutputStream
  [^OutputStream output cipher encryptors & opts]
  (let [encryptors (arg-coll encryptors)
        {:keys [buffer-size integrity-packet random]
         :or {buffer-size 4096
              integrity-packet true}}
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
            integrity-packet (.setWithIntegrityPacket true)
            random           (.setSecureRandom ^SecureRandom random)))
        encryptors)
      output
      (byte-array buffer-size))))


(extend-protocol MessagePacket

  PGPEncryptedDataList

  ;; Read through the list of encrypted session keys and attempt to find one
  ;; which the decryptor will unlock. If none are found, the message is not
  ;; decipherable and an exception is thrown.

  (reduce-message
    [packet opts rf acc]
    (if-let [readable-packet (readable packet opts)]
      (reduce-message readable-packet opts rf acc)
      (throw (IllegalArgumentException.
               (str "Cannot decrypt " (pr-str packet) " with " (pr-str opts)
                    " (no matching encrypted session key)")))))

  (readable
    [packet opts]
    (some
      #(readable % opts)
      (iterator-seq (.getEncryptedDataObjects packet))))


  PGPPBEEncryptedData

  (reduce-message
    [packet {:keys [decryptor] :as opts} rf acc]
    (let [decryptor-factory (BcPBEDataDecryptorFactory.
                              (.toCharArray ^String decryptor)
                              (BcPGPDigestCalculatorProvider.))
          cipher (-> packet
                     (.getSymmetricAlgorithm decryptor-factory)
                     tags/symmetric-key-algorithm-tag)]
      (reduce-content
        (.getDataStream packet decryptor-factory)
        opts
        (with-reduce-attrs rf :cipher cipher :object packet)
        acc)))

  ;; If the decryptor is a string, try to use it to decrypt the passphrase
  ;; protected session key.
  (readable
    [packet {:keys [decryptor] :as opts}]
    (when (string? decryptor)
      packet))


  PGPPublicKeyEncryptedData

  (reduce-message
    [packet {:keys [decryptor] :as opts} rf acc]
    (let [for-key (.getKeyID packet)
          privkey (pgp/private-key
                    (if (ifn? decryptor)
                      (decryptor for-key)
                      decryptor))
          decryptor-factory (BcPublicKeyDataDecryptorFactory. privkey)
          cipher (-> packet
                     (.getSymmetricAlgorithm decryptor-factory)
                     tags/symmetric-key-algorithm-tag)]
      (reduce-content
        (.getDataStream packet decryptor-factory)
        opts
        (with-reduce-attrs rf
          :encrypted-for for-key
          :cipher cipher
          :object packet)
        acc)))

  ;; If the decryptor is callable, use it to find a private key matching the id
  ;; on the data packet. Otherwise, use it directly as a private key. If the
  ;; decryptor doesn't match the id, return nil.
  (readable
    [packet {:keys [decryptor] :as opts}]
    (let [for-key (.getKeyID packet)]
      (when (some-> (if (ifn? decryptor)
                      (decryptor for-key)
                      decryptor)
                    (pgp/private-key)
                    (pgp/key-id)
                    (= for-key))
        packet))))



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
      (close
        []
        (dorun (map #(.close ^OutputStream %) streams))))))


(defn package
  "Compresses, encrypts, and encodes the given data and returns an encoded
  message packet. If the `:armor` option is set, the result will be an ASCII
  string; otherwise, the function returns a byte array.

  The message will readable by any of the corresponding decryptors.

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
  (apply package data
         :encryptors encryptors
         opts))



;; ## Reading PGP Messages

(defn- reduce-objects
  "Reduces over the PGP objects the returns the resulting accumulator.
  Verifys the integrity of each object and throws if its invalid."
  [opts rf acc objects]
  (reduce
    (fn reduce-and-verify!
      [acc message]
      (reduce-message
        message
        opts
        (fn [acc {:keys [object] :as message}]
          ;; To be able to verify the integrity we must have consumed the stream itself.
          ;; Make sure to call the reducing function and then verify the message.
          (let [results (rf acc message)]
            (when (and (instance? PGPEncryptedData object)
                       (.isIntegrityProtected object)
                       (not (.verify object)))
              (throw (IllegalStateException.
                       (str "Encrypted data object " object
                            " failed integrity verification!"))))
            results))
        acc))
    acc
    objects))


(defn reduce-messages
  "Reads message packets form an input source and reduces over them with the
  given accumulator `acc` and reducing function `rf`. Each message contains
  keys similiar to the options used to build them, describing the type of compression used,
  cophier encrypted with, etc. The `rf` should take the accumulator and a `message` and
  return the resulting accumulator. It must consume the stream passed in the `:data` field.
  A message is a map containing:
  - `:format` one of #{:binary :text :utf8}
  - `:data` An InputStream
  - `:filename` the name of the file
  - `:mtime` the modified time of the message

  Opts may contain:

  - `:decryptor` secret to decipher the message encryption"
  [input rf acc & opts]
  (->> input
       bytes/to-input-stream
       PGPUtil/getDecoderStream
       pgp/read-objects
       (reduce-objects (apply hash-map opts) rf acc)))


(defn read-messages
  "Reads message packets from an input source and returns a sequence of message
  maps which have realized `:data` entries.

  See `reduce-messages` for options
  "
  [input & opts]
  (apply
    reduce-messages
    input
    (fn [acc {:keys [format data] :as message}]
      (let [data' (bytes/to-byte-array data)]
        (->> (case format
               (:text :utf8) (String. data')
               data')
             (assoc message :data)
             (conj acc))))
    []
    opts))


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
