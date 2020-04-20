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

  (list-public-keys
    [this]
    "Enumerates the available public keys.")

  (list-secret-keys
    [this]
    "Enumerates the available secret keys.")

  (get-public-key
    [this id]
    "Loads a public key by id.")

  (get-secret-key
    [this id]
    "Loads a secret key by id."))



;; ## Public Key Rings

(defn public-keyring-coll
  "Wraps the collection of public keyrings in a `PGPPublicKeyRingCollection`."
  ([]
   (public-keyring-coll nil))
  ([keyrings]
   (PGPPublicKeyRingCollection. keyrings)))


(defn load-public-keyring
  "Loads a public keyring collection from a data source."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream source))]
    (PGPPublicKeyRingCollection. stream (BcKeyFingerprintCalculator.))))


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
    (mapcat list-public-keys this))

  (get-public-key
    [this id]
    (.getPublicKey this (pgp/key-id id)))


  pgp/Encodable

  (encode
    [this]
    (.getEncoded this)))



;; ## Secret Key Rings

(defn secret-keyring-coll
  "Wraps the collection of public keyrings in a `PGPPublicKeyRingCollection`."
  ([]
   (secret-keyring-coll nil))
  ([keyrings]
   (PGPPublicKeyRingCollection. keyrings)))


(defn load-secret-keyring
  "Loads a secret keyring collection from a data source."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (bytes/to-input-stream source))]
    (PGPSecretKeyRingCollection. stream (BcKeyFingerprintCalculator.))))


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
    (mapcat list-public-keys this))

  (list-secret-keys
    [this]
    (mapcat list-secret-keys this))

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
