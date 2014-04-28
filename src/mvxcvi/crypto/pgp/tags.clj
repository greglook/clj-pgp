(ns mvxcvi.crypto.pgp.tags
  (:require
    [clojure.string :as str])
  (:import
    (org.bouncycastle.bcpg
      CompressionAlgorithmTags
      HashAlgorithmTags
      PublicKeyAlgorithmTags
      SymmetricKeyAlgorithmTags)))


;; TAG FUNCTIONS

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


(defn- tag-code
  "Coerces the argument into a numeric tag code."
  [tag-name tags value]
  (cond
    (keyword? value)
    (if-let [code (tags value)]
      code
      (throw (IllegalArgumentException.
               (str "Invalid " tag-name " name " value))))

    (number? value)
    (if (contains? (set (vals tags)) value)
      value
      (throw (IllegalArgumentException.
               (str "Invalid " tag-name " code " value))))

    :else
    (throw (IllegalArgumentException.
             (str "Unknown " tag-name " identifier " value)))))


(defn lookup
  "Looks up the keyword of an algorithm given the numeric code."
  [codes code]
  (some #(if (= (val %) code) (key %)) codes))



;; TAG DEFINITIONS

(defmacro deftags
  [cls]
  (let [tag-name (-> (name cls)
                     (as-> s (subs s 0 (- (count s) 4)))
                     (str/replace #"([a-z])([A-Z])" "$1-$2")
                     str/lower-case
                     symbol)
        tag-map (symbol (str tag-name \s))]
    `(do
       (def ~tag-map
         (map-tags ~cls))
       (defn ~tag-name
         [value#]
         (tag-code ~(str tag-name) ~tag-map value#)))))


(deftags CompressionAlgorithmTags)
(deftags HashAlgorithmTags)
(deftags PublicKeyAlgorithmTags)
(deftags SymmetricKeyAlgorithmTags)
