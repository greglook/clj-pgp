(ns mvxcvi.crypto.pgp.codec-test
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as keys])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKey)))


(def pubkey
  (pgp/get-public-key keys/pubring "923b1c1c4392318a"))


(deftest public-key-encoding
  (let [encoded-key (pgp/encode pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (instance? PGPPublicKey decoded-key))
    (is (bytes= encoded-key (pgp/encode decoded-key))))
  (let [encoded-key (pgp/encode-ascii pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (string? encoded-key))
    (is (instance? PGPPublicKey decoded-key))
    (is (= encoded-key (pgp/encode-ascii decoded-key)))))


(deftest signature-encoding
  (is (thrown? IllegalArgumentException
               (pgp/decode-signature (pgp/encode pubkey)))))
