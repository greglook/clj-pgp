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
  "Generates a PGP signature from the given data and private key."
  [data hash-algo ^PGPPrivateKey privkey]
  (let [generator (PGPSignatureGenerator.
                    (BcPGPContentSignerBuilder.
                      (tags/public-key-algorithms (key-algorithm privkey))
                      (tags/hash-algorithms hash-algo)))]
    (.init generator PGPSignature/BINARY_DOCUMENT privkey)
    (apply-bytes data
      (fn [^bytes buff ^long n]
        (.update generator buff 0 n)))
    (.generate generator)))


(defn verify
  "Verifies a PGP signature. Returns true if the signature is correct."
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
