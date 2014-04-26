(ns mvxcvi.crypto.pgp.keyring
  (:require
    byte-streams
    [mvxcvi.crypto.pgp.key :refer [key-id]])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKey
      PGPPublicKeyRing
      PGPPublicKeyRingCollection
      PGPSecretKey
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPUtil)))


(defprotocol KeyRing
  "Protocol for obtaining PGP keys."

  (list-public-keys [this]
    "Enumerates the available public keys.")

  (list-secret-keys [this]
    "Enumerates the available secret keys.")

  (get-public-key
    ^PGPPublicKey
    [this id]
    "Loads a public key by id.")

  (get-secret-key
    ^PGPSecretKey
    [this id]
    "Loads a secret key by id."))


(extend-protocol KeyRing
  PGPPublicKeyRing

  (list-public-keys [this]
    (->> this .getPublicKeys iterator-seq))

  (get-public-key [this id]
    (.getPublicKey this (key-id id)))

  PGPPublicKeyRingCollection

  (list-public-keys [this]
    (->> this .getKeyRings iterator-seq (map list-public-keys) flatten))

  (get-public-key [this id]
    (.getPublicKey this (key-id id)))

  PGPSecretKeyRing

  (list-public-keys [this]
    (->> this .getPublicKeys iterator-seq))

  (list-secret-keys [this]
    (->> this .getSecretKeys iterator-seq))

  (get-public-key [this id]
    (.getPublicKey this (key-id id)))

  (get-secret-key [this id]
    (.getSecretKey this (key-id id)))

  PGPSecretKeyRingCollection

  (list-public-keys [this]
    (->> this .getKeyRings iterator-seq (map list-public-keys) flatten))

  (list-secret-keys [this]
    (->> this .getKeyRings iterator-seq (map list-secret-keys) flatten))

  (get-public-key [this id]
    (let [id (key-id id)]
      (-> this (.getSecretKeyRing id) (.getPublicKey id))))

  (get-secret-key [this id]
    (.getSecretKey this (key-id id))))


(defn load-public-keyring
  "Loads a public keyring collection from a file."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (byte-streams/to-input-stream source))]
    (PGPPublicKeyRingCollection. stream)))


(defn load-secret-keyring
  "Loads a secret keyring collection from a file."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (byte-streams/to-input-stream source))]
    (PGPSecretKeyRingCollection. stream)))
