(ns clj-pgp.tags
  "Vars which map Cloure keywords to numeric BouncyCastle tag codes."
  (:require
    [clojure.string :as str])
  (:import
    (org.bouncycastle.bcpg
      CompressionAlgorithmTags
      HashAlgorithmTags
      PublicKeyAlgorithmTags
      SymmetricKeyAlgorithmTags)))


;; ## Tag Functions

(defn- map-tags
  "Convert static 'tag' fields on the given class into a map of keywords to
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


(defn tag->code
  "Coerce a value into a numeric tag code. The argument may be a keyword or a
  number. If the tag map does not contain the value, an exception is thrown."
  ^Integer
  [tag-name tags value]
  (cond
    (keyword? value)
    (if-let [code (tags value)]
      code
      (throw (IllegalArgumentException.
               (str "Invalid " tag-name " name " value))))

    (number? value)
    (if (some #{value} (vals tags))
      value
      (throw (IllegalArgumentException.
               (str "Invalid " tag-name " code " value))))

    :else
    (throw (IllegalArgumentException.
             (str "Unknown " tag-name " identifier: " (pr-str value))))))


(defn code->tag
  "Look up the keyword for a tag from the numeric code."
  [tags code]
  (some #(when (= (val %) code) (key %)) tags))



;; ## Tag Definitions

(defmacro ^:private deftags
  "Defines a tag map and coersion function from fields on the given class."
  [cls]
  (let [tag-name (-> (name cls)
                     (as-> s (subs s 0 (- (count s) 4)))
                     (str/replace #"([a-z])([A-Z])" "$1-$2")
                     str/lower-case
                     symbol)
        tag-map (symbol (str tag-name "-tags"))]
    `(do
       (def ~tag-map
         ~(str "Map of " tag-name " tag codes.")
         (map-tags ~cls))
       (defn ~(symbol (str tag-name "-code"))
         ~(str "Validate and coerce the argument into a " tag-name " tag code.")
         ^Integer
         [~'value]
         (tag->code ~(str tag-name) ~tag-map ~'value))
       (defn ~(symbol (str tag-name "-tag"))
         ~(str "Validate and coerce the argument into a " tag-name " tag keyword.")
         [~'value]
         (code->tag ~tag-map (tag->code ~(str tag-name) ~tag-map ~'value))))))


(deftags HashAlgorithmTags)
(deftags CompressionAlgorithmTags)
(deftags PublicKeyAlgorithmTags)
(deftags SymmetricKeyAlgorithmTags)
