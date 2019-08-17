(ns clj-pgp.signature
  "The functions in this namespace generate and verify PGP signatures."
  (:require
    [byte-streams :as bytes]
    [clj-pgp.core :as pgp]
    [clj-pgp.tags :as tags]
    [clj-pgp.util :refer [arg-map]])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSignature
      PGPSignatureGenerator)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPContentSignerBuilder
      BcPGPContentVerifierBuilderProvider)))


;; ## Signature Utilities

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



;; ## Provider Protocol

(defprotocol SignatureProvider
  "This protocol provides a generic way to provide signature creation.

  The simple approach is to use unlocked private keys directly, but this allows
  for more nuanced approaches such as interfacing with gpg-agent, TPMs, or
  other secret-holding services."

  (create-signature
    [provider data opts]
    "Produces a PGP signature by hashing the data with a digest algorithm and
    encrypting the digest with a private key.

    If the `:key-id` option is not specified, some default signing key should
    be used. Throws an exception if a matching key cannot be used."))


(defn sign
  "Signs data with the given provider and options. The `provider` must either be
  coerceable into a private key or implement the `SignatureProvider` protocol.

  - `:hash-algo` digest algorithm to hash the data with
  - `:key-id`    identifier of the desired signature key"
  [data provider & opts]
  (let [provider (or (pgp/private-key provider) provider)
        opts (merge {:hash-algo :sha1}
                    (arg-map opts))]
    (create-signature provider data opts)))


(defn verify
  "Verifies a PGP signature. Returns true if the data was signed by the private
  key matching the given public key."
  [data ^PGPSignature signature pubkey]
  (when-not (= (pgp/key-id signature) (pgp/key-id pubkey))
    (throw (IllegalArgumentException.
             (str "Signature key id " (pgp/hex-id signature)
                  " doesn't match provided key id " (pgp/hex-id pubkey)))))
  (.init signature
         (BcPGPContentVerifierBuilderProvider.)
         ^PGPPublicKey (pgp/public-key pubkey))
  (apply-bytes data (.update signature buffer 0 n))
  (.verify signature))



;; ## Private-Key Signatures

;; Private keys can be used to directly provide signatures on data. The
;; default signing key is the provided key itself, so if an explicit identifier
;; is provided which doesn't match the key id, an error is thrown.
(extend-protocol SignatureProvider

  PGPPrivateKey

  (create-signature
    [privkey data {:keys [hash-algo key-id]}]
    (when (and key-id (not= key-id (pgp/key-id privkey)))
      (throw (IllegalArgumentException.
               (str "Desired signing key " (pgp/hex-id key-id) " does not match "
                    "private key " (pgp/hex-id privkey)))))
    (let [generator (PGPSignatureGenerator.
                      (BcPGPContentSignerBuilder.
                        (tags/public-key-algorithm-code (pgp/key-algorithm privkey))
                        (tags/hash-algorithm-code hash-algo)))]
      (.init generator
             PGPSignature/BINARY_DOCUMENT
             privkey)
      (apply-bytes data (.update generator buffer 0 n))
      (.generate generator))))
