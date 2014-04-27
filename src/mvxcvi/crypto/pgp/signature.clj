(ns mvxcvi.crypto.pgp.signature
  (:require
    (mvxcvi.crypto.pgp
      [key :refer [key-algorithm key-id]]
      [tags :as tags]
      [util :refer [do-bytes hex-str]]))
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
  "Generates a PGPSignature from the given data and private key."
  ^PGPSignature
  [data hash-algo ^PGPPrivateKey privkey]
  (let [generator (PGPSignatureGenerator.
                    (BcPGPContentSignerBuilder.
                      (tags/public-key-algorithms (key-algorithm privkey))
                      (tags/hash-algorithms hash-algo)))]
    (.init generator PGPSignature/BINARY_DOCUMENT privkey)
    (do-bytes [[buf n] data]
      (.update generator buf 0 n))
    (.generate generator)))


(defn verify
  [data
   ^PGPSignature signature
   ^PGPPublicKey pubkey]
  (when-not (= (key-id signature) (key-id pubkey))
    (throw (IllegalArgumentException.
             (str "Signature key id "
                  (hex-str (key-id signature))
                  " doesn't match public key id "
                  (hex-str (key-id pubkey))))))
  (.init signature
         (BcPGPContentVerifierBuilderProvider.)
         pubkey)
  (do-bytes [[buf n] data]
    (.update signature buf 0 n))
  (.verify signature))
