(ns mvxcvi.crypto.pgp.codec-test
  (:require
    [byte-streams :refer [bytes=]]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as keys])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKey)))


(def pubkey
  (pgp/get-public-key keys/pubring "923b1c1c4392318a"))


(facts "public-key binary encoding"
  (let [encoded-key (pgp/encode pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (fact "key is decoded as a PGP public key"
      decoded-key => (partial instance? PGPPublicKey))
    (fact "encoded key is canonical"
      (pgp/encode decoded-key) => (partial bytes= encoded-key))))


(facts "public-key ascii encoding"
  (let [encoded-key (pgp/encode-ascii pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (fact "key is encoded as a string"
      encoded-key => string?)
    (fact "key is decoded as a PGP public key"
      decoded-key => (partial instance? PGPPublicKey))
    (fact "encoded key is canonical"
      (pgp/encode-ascii decoded-key) => encoded-key)))


(facts "signature encoding"
  (fact "decoding non-signature value throws an exception"
    (pgp/decode-signature (pgp/encode pubkey))
    => (throws IllegalArgumentException)))
