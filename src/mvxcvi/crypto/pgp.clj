(ns mvxcvi.crypto.pgp
  "Functions for interacting with BouncyCastle's OpenPGP library."
  (:require
    byte-streams
    [clojure.java.io :as io]
    [clojure.string :as str]
    [mvxcvi.crypto.util :refer [do-bytes hex-str]])
  (:import
    (java.io
      ByteArrayOutputStream)
    (org.bouncycastle.bcpg
      ArmoredOutputStream
      BCPGOutputStream
      HashAlgorithmTags
      PublicKeyAlgorithmTags)
    (org.bouncycastle.openpgp
      PGPKeyRing
      PGPObjectFactory
      PGPPrivateKey
      PGPPublicKey
      PGPPublicKeyRing
      PGPPublicKeyRingCollection
      PGPSecretKey
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPSignature
      PGPSignatureGenerator
      PGPSignatureList
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcPGPContentSignerBuilder
      BcPGPContentVerifierBuilderProvider
      BcPGPDigestCalculatorProvider
      BcPBESecretKeyDecryptorBuilder)))


(load "pgp/conf")
(load "pgp/key")
(load "pgp/keyring")
(load "pgp/signature")
(load "pgp/io")
