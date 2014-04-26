(in-ns 'mvxcvi.crypto.pgp)


(defn sign
  "Generates a PGPSignature from the given data and private key."
  ^PGPSignature
  [data hash-algo ^PGPPrivateKey privkey]
  (let [generator (PGPSignatureGenerator.
                    (BcPGPContentSignerBuilder.
                      (public-key-algorithms (key-algorithm privkey))
                      (hash-algorithms hash-algo)))]
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
                  (Long/toHexString (key-id signature))
                  " doesn't match public key id "
                  (Long/toHexString (key-id pubkey))))))
  (.init signature
         (BcPGPContentVerifierBuilderProvider.)
         pubkey)
  (do-bytes [[buf n] data]
    (.update signature buf 0 n))
  (.verify signature))
