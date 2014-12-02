(ns clj-pgp.test.tags
  (:require
    [clojure.test :refer :all]
    [clj-pgp.tags :as tags]))


(defmacro ^:private check-tags
  [tag-map]
  `(deftest ~(symbol (str "well-formed-" (name tag-map)))
     (is (not (empty? ~tag-map))
         "tag map is not empty")
     (is (every? keyword? (keys ~tag-map))
         "tag map keys are all keywords")
     (is (every? integer? (vals ~tag-map))
         "tag map values are integers")))


(check-tags tags/compression-algorithms)
(check-tags tags/hash-algorithms)
(check-tags tags/public-key-algorithms)
(check-tags tags/symmetric-key-algorithms)


(deftest tag-coercion
  (is (= 3 (tags/compression-algorithm :bzip2))
    "keyword lookup returns numeric code")
  (is (= 1 (tags/compression-algorithm 1))
      "numeric lookup returns numeric value")
  (testing "unknown tag throws exception"
    (are [v] (thrown? IllegalArgumentException
                      (tags/compression-algorithm v))
         :foo 82 "abcd")))


(deftest tag-lookup
  (let [tag (first tags/public-key-algorithms)]
    (is (= (key tag) (tags/lookup tags/public-key-algorithms (val tag)))
        "tag lookup by value returns key")))
