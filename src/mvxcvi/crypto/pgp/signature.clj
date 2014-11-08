(ns mvxcvi.crypto.pgp.signature
  "Signature generation and verification."
  (:require
    (mvxcvi.crypto.pgp
      [io :refer [apply-bytes]]
      [tags :as tags]
      [util :refer [hex-id key-algorithm key-id]]))
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSignature
      PGPSignatureGenerator)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPContentSignerBuilder
      BcPGPContentVerifierBuilderProvider)))


(defn sign
  "Creates a PGP signature by the given key. The data is first hashed with the
  given algorithm, then the digest is signed by the private key."
  [data hash-algo ^PGPPrivateKey privkey]
  (let [generator (PGPSignatureGenerator.
                    (BcPGPContentSignerBuilder.
                      (tags/public-key-algorithm (key-algorithm privkey))
                      (tags/hash-algorithm hash-algo)))]
    (.init generator PGPSignature/BINARY_DOCUMENT privkey)
    (apply-bytes data
      (fn [^bytes buff ^long n]
        (.update generator buff 0 n)))
    (.generate generator)))


(defn verify
  "Verifies a PGP signature. Returns true if the data was signed by the private
  key matching the given public key."
  [data
   ^PGPSignature signature
   ^PGPPublicKey pubkey]
  (when-not (= (key-id signature) (key-id pubkey))
    (throw (IllegalArgumentException.
             (str "Signature key id "
                  (hex-id signature)
                  " doesn't match public key id "
                  (hex-id pubkey)))))
  (.init signature
         (BcPGPContentVerifierBuilderProvider.)
         pubkey)
  (apply-bytes data
    (fn [^bytes buff ^long n]
      (.update signature buff 0 n)))
  (.verify signature))
