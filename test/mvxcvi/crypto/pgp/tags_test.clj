(ns mvxcvi.crypto.pgp.tags-test
  (:require
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp.tags :as tags]))


(defmacro check-tags
  [tag-map]
  `(fact ~(str "tag map " (name tag-map) " is well-formed")
     ~tag-map =not=> empty?
     (keys ~tag-map) => (has every? keyword?)
     (vals ~tag-map) => (has every? number?)))


(facts "tag maps"
  (check-tags tags/compression-algorithms)
  (check-tags tags/hash-algorithms)
  (check-tags tags/public-key-algorithms)
  (check-tags tags/symmetric-key-algorithms))


(facts "tag coercion"
  (fact "keyword lookup returns numeric code"
    (tags/compression-algorithm :bzip2) => 3)
  (fact "numeric lookup returns numeric value"
    (tags/compression-algorithm 1) => 1)
  (fact "unknown tag throws exception"
    (tags/compression-algorithm :foo)   => (throws IllegalArgumentException)
    (tags/compression-algorithm 82)     => (throws IllegalArgumentException)
    (tags/compression-algorithm "abcd") => (throws IllegalArgumentException)))


(facts "tag lookup"
  (let [tag (first tags/public-key-algorithms)]
    (fact "tag lookup by value returns key"
      (tags/lookup tags/public-key-algorithms (val tag)) => (key tag))))
