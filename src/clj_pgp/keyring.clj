(ns clj-pgp.keyring
  "This namespace handles interactions with PGP keyrings.

  Literal keyring files are directly supported, and key servers and other
  stores can extend the `KeyRing` protocol for further extension."
  (:require
    [byte-streams :as bytes]
    [clj-pgp.core :as pgp])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPPublicKeyRingCollection
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPUtil)
    (org.bouncycastle.openpgp.operator.bc
      BcKeyFingerprintCalculator)))


(defprotocol KeyRing
  "Protocol for obtaining PGP keys."

  (list-public-keys [this]
    "Enumerates the available public keys.")

  (list-secret-keys [this]
    "Enumerates the available secret keys.")

  (get-public-key [this id]
    "Loads a public key by id.")

  (get-secret-key [this id]
    "Loads a secret key by id."))


(extend-type PGPPublicKeyRing

  KeyRing

  (list-public-keys
    [this]
    (iterator-seq (.getPublicKeys this)))

  (get-public-key
    [this id]
    (.getPublicKey this (pgp/key-id id)))


  pgp/Encodable

  (encode
    [this]
    (.getEncoded this)))


(extend-type PGPPublicKeyRingCollection

  KeyRing

  (list-public-keys
    [this]
    (->> (iterator-seq (.getKeyRings this))
         (mapcat list-public-keys)))

  (get-public-key
    [this id]
    (.getPublicKey this (pgp/key-id id)))


  pgp/Encodable

  (encode
    [this]
    (.getEncoded this)))


(extend-type PGPSecretKeyRing

  KeyRing

  (list-public-keys
    [this]
    (iterator-seq (.getPublicKeys this)))

  (list-secret-keys
    [this]
    (iterator-seq (.getSecretKeys this)))

  (get-public-key
    [this id]
    (.getPublicKey this (pgp/key-id id)))

  (get-secret-key
    [this id]
    (.getSecretKey this (pgp/key-id id)))



  pgp/Encodable

  (encode
    [this]
    (.getEncoded this)))


(extend-type PGPSecretKeyRingCollection

  KeyRing

  (list-public-keys
    [this]
    (->> (iterator-seq (.getKeyRings this))
         (mapcat list-public-keys)))

  (list-secret-keys
    [this]
    (->> (iterator-seq (.getKeyRings this))
         (mapcat list-secret-keys)))

  (get-public-key
    [this id]
    (let [id (pgp/key-id id)]
      (-> this (.getSecretKeyRing id) (.getPublicKey id))))

  (get-secret-key
    [this id]
    (.getSecretKey this (pgp/key-id id)))


  pgp/Encodable

  (encode
    [this]
    (.getEncoded this)))



;; ## Loading Functions

(defn load-public-keyring
  "Loads a public keyring collection from a data source."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream source))]
    (PGPPublicKeyRingCollection. stream (BcKeyFingerprintCalculator.))))


(defn load-secret-keyring
  "Loads a secret keyring collection from a data source."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream source))]
    (PGPSecretKeyRingCollection. stream (BcKeyFingerprintCalculator.))))
