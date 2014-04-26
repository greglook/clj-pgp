(ns mvxcvi.crypto.pgp.conf-test
  (:require
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]))


(deftest public-key-algorithm-tags
  (is (not (empty? pgp/public-key-algorithms)))
  (is (every? keyword? (keys pgp/public-key-algorithms)))
  (is (every? number? (vals pgp/public-key-algorithms))))


(deftest hash-algorithm-tags
  (is (not (empty? pgp/hash-algorithms)))
  (is (every? keyword? (keys pgp/hash-algorithms)))
  (is (every? number? (vals pgp/hash-algorithms))))
