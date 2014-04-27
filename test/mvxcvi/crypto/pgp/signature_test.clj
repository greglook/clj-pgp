(ns mvxcvi.crypto.pgp.signature-test
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as keys])
  (:import
    (org.bouncycastle.openpgp
      PGPSignature)))


(deftest signature-functions
  (let [seckey (pgp/get-secret-key keys/secring "3f40edec41c6cb7d")
        data "cryptography is neat"
        privkey (pgp/unlock-key seckey "test password")
        sig (pgp/sign data :sha1 privkey)]
    (is (= (pgp/key-id privkey) (pgp/key-id sig)))
    (let [wrong-pubkey (pgp/get-public-key keys/pubring "923b1c1c4392318a")]
      (is (thrown? IllegalArgumentException
                   (pgp/verify data sig wrong-pubkey))))
    (is (pgp/verify data sig (pgp/public-key seckey)))
    (testing "signature encoding"
      (let [binary (pgp/encode sig)
            sig' (pgp/decode-signature binary)]
        (is (bytes= (.getSignature sig)
                    (.getSignature sig')))
        (is (pgp/verify data sig' (pgp/public-key seckey)))))))
