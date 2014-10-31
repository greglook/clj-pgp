(ns mvxcvi.crypto.pgp.generate
  (:require
    [clojure.string :as str]
    (mvxcvi.crypto.pgp
      [tags :as tags]
      [util :refer [hex-str]]))
  (:import
    (java.security
      SecureRandom)
    (org.bouncycastle.crypto.generators
      RSAKeyPairGenerator)
    (org.bouncycastle.crypto.params
      RSAKeyGenerationParameters
      RSAKeyParameters
      RSAPrivateCrtKeyParameters)
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)
    #_
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyEncryptorBuilder
      BcPGPDigestCalculatorProvider)))


;; ## Key Generation

(defn generate-rsa-keypair
  "Generates a new RSA PGP keypair."
  [& {:keys [strength random]
      :or {strength 1024
           random (SecureRandom/getInstance "SHA1PRNG")}}]
  (let [params (RSAKeyGenerationParameters.
                 (BigInteger. "10001" 16)
                 random
                 strength
                 80)
        keypair-params (-> (RSAKeyPairGenerator.)
                           (doto (.init params))
                           (.generateKeyPair))
        ]
    ; keypair-params => o.b.c.AsymmetricCipherKeyPair
    ; (.getPublic keypair-params) => o.b.c.params.RSAKeyParameters
    ; (.getPrivate keypair-params) => o.b.c.params.RSAPrivateCrtKeyParameters
    ; ...
    ; convert to o.b.b.RSAPublicBCPGKey (modulus n, exponent e)
    ; convert to o.b.b.RSASecretBCPGKey (d, p, q)
    )

  ; TODO: convert to PGP keypair
  )
