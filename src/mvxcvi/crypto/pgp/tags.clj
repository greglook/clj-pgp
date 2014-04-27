(ns mvxcvi.crypto.pgp.tags
  (:require
    [clojure.string :as str])
  (:import
    (org.bouncycastle.bcpg
      HashAlgorithmTags
      PublicKeyAlgorithmTags)))


(defn- map-tags
  "Converts static 'tag' fields on the given class into a map of keywords to
  numeric codes."
  [^Class tags]
  (let [field->entry
        (fn [^java.lang.reflect.Field f]
          (vector (-> (.getName f)
                      (str/replace \_ \-)
                      .toLowerCase
                      keyword)
                  (.getInt f nil)))]
    (->> (.getFields tags)
         (map field->entry)
         (into {}))))


(defn lookup
  "Looks up the keyword of an algorithm given the numeric code."
  [codes code]
  (some #(if (= (val %) code) (key %)) codes))


(def public-key-algorithms
  "Map of public-key algorithm names to numeric codes."
  (map-tags PublicKeyAlgorithmTags))


(def hash-algorithms
  "Map of hash algorithm keywords to numeric codes."
  (map-tags HashAlgorithmTags))
