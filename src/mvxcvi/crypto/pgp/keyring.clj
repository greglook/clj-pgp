(ns mvxcvi.crypto.pgp.keyring
  "Keyring store implementation."
  (:require
    byte-streams
    [clojure.java.io :as io]
    [mvxcvi.crypto.pgp :as pgp :refer [KeyStore]])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKeyRing
      PGPPublicKeyRingCollection
      PGPSecretKeyRing
      PGPSecretKeyRingCollection
      PGPUtil)))


;; KEYRING UTILITIES

(defn- load-public-keyrings
  "Loads a public keyring file into a sequence of vectors of public keys."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (byte-streams/to-input-stream source))]
    (map (fn [^PGPPublicKeyRing keyring]
           (vec (iterator-seq (.getPublicKeys keyring))))
         (-> stream
             PGPPublicKeyRingCollection.
             .getKeyRings
             iterator-seq))))


(defn- load-secret-keyrings
  "Loads a secret keyring file into a sequence of vectors of secret keys."
  [source]
  (with-open [stream (PGPUtil/getDecoderStream
                       (byte-streams/to-input-stream source))]
    (map (fn [^PGPSecretKeyRing keyring]
           (vec (iterator-seq (.getSecretKeys keyring))))
         (-> stream
             PGPSecretKeyRingCollection.
             .getKeyRings
             iterator-seq))))


(defn- find-key
  "Locates a key in a sequence by id. Nested sequences are flattened, so this
  works directly on keyrings and keyring collections."
  [id key-seq]
  (let [id (pgp/key-id id)]
    (some #(when (= id (pgp/key-id %)) %)
          (flatten key-seq))))



;; KEYRING STORE

(defrecord PGPKeyring [pubring secring])

(extend-protocol KeyStore
  PGPKeyring

  (list-public-keys [this]
    (-> this :pubring load-public-keyrings flatten))

  (get-public-key [this id]
    (->> this :pubring load-public-keyrings (find-key id)))

  (list-secret-keys [this]
    (-> this :secring load-secret-keyrings flatten))

  (get-secret-key [this id]
    (->> this :secring load-secret-keyrings (find-key id))))


(defn pgp-keyring
  "Constructs a PGPKeyring for the given keyring files."
  [pubring secring]
  (->PGPKeyring (io/file pubring) (io/file secring)))
