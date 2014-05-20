(ns mvxcvi.crypto.pgp.tags-test
  (:require
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp.tags :as tags]))


(defn check-tags
  [tag-map]
  (is (not (empty? tag-map)))
  (is (every? keyword? (keys tag-map)))
  (is (every? number?  (vals tag-map))))


(deftest compression-algorithm-tags
  (check-tags tags/compression-algorithms))

(deftest hash-algorithm-tags
  (check-tags tags/hash-algorithms))

(deftest public-key-algorithm-tags
  (check-tags tags/public-key-algorithms))

(deftest symmetric-key-algorithm-tags
  (check-tags tags/symmetric-key-algorithms))


(deftest tag-coercion
  (is (= 3 (tags/compression-algorithm :bzip2)))
  (is (thrown? IllegalArgumentException (tags/compression-algorithm :foo)))
  (is (= 1 (tags/compression-algorithm 1)))
  (is (thrown? IllegalArgumentException (tags/compression-algorithm 82)))
  (is (thrown? IllegalArgumentException (tags/compression-algorithm "abcd"))))


(deftest lookup-tag
  (let [tag (first tags/public-key-algorithms)]
    (is (= (key tag) (tags/lookup tags/public-key-algorithms (val tag))))))
