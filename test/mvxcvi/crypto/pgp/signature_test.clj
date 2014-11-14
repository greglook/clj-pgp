(ns mvxcvi.crypto.pgp.signature-test
  (:require
    [byte-streams :refer [bytes=]]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :refer [master-pubkey pubkey privkey]]))


(facts "signature verification"
  (let [data "cryptography is neat"
        sig (pgp/sign data privkey)]
    (fact "signature key-id matches key"
      (pgp/key-id sig) => (pgp/key-id privkey))
    (fact "verification with the wrong public key throws error"
      (pgp/verify data sig master-pubkey)
      => (throws IllegalArgumentException))
    (fact "verification with public key succeeds"
      (pgp/verify data sig pubkey) => true)))


(facts "signature encoding"
  (let [data "very important data to trust"
        sig (pgp/sign data privkey)
        binary (pgp/encode sig)
        sig' (pgp/decode-signature binary)]
    (fact "binary representation is canonical"
      (pgp/encode sig') => (partial bytes= binary))
    (fact "decoded signature can be verified"
      (pgp/verify data sig' pubkey) => true)
    (fact "decoding non-signature value throws an exception"
      (pgp/decode-signature (pgp/encode pubkey))
      => (throws IllegalArgumentException))))
