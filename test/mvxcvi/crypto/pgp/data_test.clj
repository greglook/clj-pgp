(ns mvxcvi.crypto.pgp.data-test
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as keys])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKey)))


(deftest data-encryption
  (let [data "Mary had a little lamb, whose fleece was white as snow."
        pubkey (pgp/get-public-key keys/pubring "923b1c1c4392318a")
        ciphertext (pgp/encrypt (.getBytes data) pubkey :armor true)]
    (println (String. ciphertext))))
