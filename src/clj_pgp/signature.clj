(ns clj-pgp.signature
  "Signature generation and verification."
  (:require
    [byte-streams :as bytes]
    (clj-pgp
      [core :as pgp]
      [tags :as tags]))
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSignature
      PGPSignatureGenerator)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPContentSignerBuilder
      BcPGPContentVerifierBuilderProvider)))


(defmacro ^:private apply-bytes
  "Executes the body on chunks of the byte sequence read from the given data
  source. This is an anaphoric macro which exposes a byte array `buffer` and a
  number of bytes read into it as `n`."
  [source & body]
  `(with-open [stream# (bytes/to-input-stream ~source)]
     (let [~'buffer (byte-array 512)]
       (loop [~'n (.read stream# ~'buffer)]
         (when (pos? ~'n)
           ~@body
           (recur (.read stream# ~'buffer)))))))


(defn sign
  "Creates a PGP signature by the given key. The data is first hashed with the
  given algorithm, then the digest is signed by the private key."
  ([data privkey]
   (sign data privkey :sha1))
  ([data privkey hash-algo]
   (let [generator (PGPSignatureGenerator.
                     (BcPGPContentSignerBuilder.
                       (tags/public-key-algorithm-code (pgp/key-algorithm privkey))
                       (tags/hash-algorithm-code hash-algo)))]
     (.init generator
            PGPSignature/BINARY_DOCUMENT
            ^PGPPrivateKey (pgp/private-key privkey))
     (apply-bytes data
       (.update generator buffer 0 n))
     (.generate generator))))


(defn verify
  "Verifies a PGP signature. Returns true if the data was signed by the private
  key matching the given public key."
  [data ^PGPSignature signature pubkey]
  (when-not (= (pgp/key-id signature) (pgp/key-id pubkey))
    (throw (IllegalArgumentException.
             (str "Signature key id " (pgp/hex-id signature)
                  " doesn't match public key id " (pgp/hex-id pubkey)))))
  (.init signature
         (BcPGPContentVerifierBuilderProvider.)
         ^PGPPublicKey (pgp/public-key pubkey))
  (apply-bytes data
    (.update signature buffer 0 n))
  (.verify signature))
