(ns mvxcvi.crypto.pgp.provider
  "Key provider functions and constructors."
  (:require
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.util :refer [hex-str]]))


(defn keystore-provider
  "Constructs a key provider function which loads keys directly from a key
  store."
  [store]
  (fn
    ([id]
     (throw (IllegalArgumentException.
              (str "Cannot load private key " (hex-str id) " from key store "
                   store " without passphrase"))))
    ([id passphrase]
     (when-let [seckey (pgp/get-secret-key store id)]
       (pgp/unlock-key seckey passphrase)))))


(defn caching-provider
  "Wraps a key provider with a layer that caches loaded private keys for later
  use. This is useful for preventing requiring more than one passphrase entry."
  [provider]
  (let [cache (atom {})]
    (fn
      ([id]
       (let [id (pgp/key-id id)]
         (or (get @cache id)
             (when-let [privkey (provider id)]
               (swap! cache assoc id privkey)
               privkey))))
      ([id passphrase]
       (let [id (pgp/key-id id)]
         (or (get @cache id)
             (when-let [privkey (provider id passphrase)]
               (swap! cache assoc id privkey)
               privkey)))))))


(defn interactive-provider
  "Wraps a key provider in a layer that will request a passphrase on the
  command-line when a private key needs to be unlocked."
  [provider]
  (fn
    ([id]
     (let [id (pgp/key-id id)]
       (println "Passphrase for private key " (hex-str id) ":")
       (provider id (read-line))))
    ([id passphrase]
     (provider id passphrase))))
