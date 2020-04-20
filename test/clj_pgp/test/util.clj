(ns clj-pgp.test.util
  (:require
    [clj-pgp.util :refer [arg-coll arg-map arg-seq]]
    [clojure.test :refer [deftest is]]))


(deftest arg-coll-tests
  (is (= nil (arg-coll nil)))
  (is (= nil (arg-coll [])))
  (is (= [:foo] (arg-coll :foo)))
  (is (= [:foo :bar] (arg-coll [:foo :bar])))
  (is (= [[:baz]] (arg-coll [[:baz]]))))


(deftest arg-seq-tests
  (is (= nil (arg-seq nil)))
  (is (= nil (arg-seq [])))
  (is (= [:a] (arg-seq [:a])))
  (is (= [:a :b :c] (arg-seq [:a :b :c])))
  (is (= [:a :b :c] (arg-seq [[:a :b :c]])))
  (is (= [[:x] [:y]] (arg-seq [[:x] [:y]]))))


(deftest arg-map-tests
  (is (= nil (arg-map nil)))
  (is (= {} (arg-map [])))
  (is (= {:foo 1} (arg-map {:foo 1})))
  (is (= {:bar 2} (arg-map [{:bar 2}])))
  (is (= {:x 5, :y 7, :z 11} (arg-map [:x 5 :y 7 :z 11])))
  (is (thrown? Exception (arg-map [:foo]))))
