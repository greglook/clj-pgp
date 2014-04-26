(ns mvxcvi.crypto.pgp.tags-test
  (:require
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp.tags :as tags]))


(deftest public-key-algorithm-tags
  (is (not (empty? tags/public-key-algorithms)))
  (is (every? keyword? (keys tags/public-key-algorithms)))
  (is (every? number? (vals tags/public-key-algorithms))))


(deftest hash-algorithm-tags
  (is (not (empty? tags/hash-algorithms)))
  (is (every? keyword? (keys tags/hash-algorithms)))
  (is (every? number? (vals tags/hash-algorithms))))


(deftest lookup-tag
  (let [tag (first tags/public-key-algorithms)]
    (is (= (key tag) (tags/lookup tags/public-key-algorithms (val tag))))))
