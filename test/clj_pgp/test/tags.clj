(ns clj-pgp.test.tags
  (:require
    [clj-pgp.tags :as tags]
    [clojure.test :refer [deftest testing is are]]))


(defmacro ^:private check-tags
  [tag-map]
  `(deftest ~(symbol (str "well-formed-" (name tag-map)))
     (is (not (empty? ~tag-map))
         "tag map is not empty")
     (is (every? keyword? (keys ~tag-map))
         "tag map keys are all keywords")
     (is (every? integer? (vals ~tag-map))
         "tag map values are integers")))


(check-tags tags/compression-algorithm-tags)
(check-tags tags/hash-algorithm-tags)
(check-tags tags/public-key-algorithm-tags)
(check-tags tags/symmetric-key-algorithm-tags)


(deftest tag-coercion
  (is (= 3 (tags/compression-algorithm-code :bzip2))
      "keyword lookup returns numeric code")
  (is (= 1 (tags/compression-algorithm-code 1))
      "numeric lookup returns numeric value")
  (testing "unknown tag throws exception"
    (are [v] (thrown? IllegalArgumentException
               (tags/compression-algorithm-code v))
      :foo 82 "abcd")))


(deftest tag-lookup
  (let [tag (first tags/public-key-algorithm-tags)]
    (is (= (key tag) (tags/code->tag tags/public-key-algorithm-tags (val tag)))
        "tag lookup by value returns key")))
