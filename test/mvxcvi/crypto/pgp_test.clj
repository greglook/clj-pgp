(ns mvxcvi.crypto.pgp-test
  (:require
    [byte-streams :refer [bytes=]]
    [clojure.java.io :as io]
    [clojure.test :refer :all]
    [mvxcvi.crypto.pgp :as pgp])
  (:import
    (org.bouncycastle.openpgp
      PGPPublicKey
      PGPSignature)))

#_
(deftest list-keyring
  (let [pubkeys (pgp/list-public-keys test-keyring)]
    (is (= 2 (count pubkeys))))
  (let [seckeys (pgp/list-secret-keys test-keyring)]
    (is (= 2 (count seckeys)))))


#_
(deftest private-key-functions
  (is (thrown? org.bouncycastle.openpgp.PGPException
               (pgp/unlock-key seckey "wrong password")))
  (let [privkey (pgp/unlock-key seckey "test password")]
    (is (= (pgp/key-id privkey) (pgp/key-id seckey)))
    (is (= :rsa-general (pgp/key-algorithm privkey)))))


#_
(deftest signature-functions
  (let [data "cryptography is neat"
        privkey (pgp/unlock-key seckey "test password")
        sig (pgp/sign data privkey)]
    (is (= (pgp/key-id privkey) (pgp/key-id sig)))
    (is (thrown? IllegalArgumentException (pgp/verify data sig pubkey)))
    (is (pgp/verify data sig (pgp/public-key seckey)))
    (testing "signature encoding"
      (let [binary (pgp/encode sig)
            sig' (pgp/decode-signature binary)]
        (is (bytes= (.getSignature sig)
                    (.getSignature sig')))
        (is (pgp/verify data sig' (pgp/public-key seckey)))))))


#_
(deftest public-key-encoding
  (let [encoded-key (pgp/encode pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (instance? org.bouncycastle.openpgp.PGPPublicKey decoded-key))
    (is (bytes= encoded-key (pgp/encode decoded-key))))
  (let [encoded-key (pgp/encode-ascii pubkey)
        decoded-key (pgp/decode-public-key encoded-key)]
    (is (string? encoded-key))
    (is (instance? org.bouncycastle.openpgp.PGPPublicKey decoded-key))
    (is (= encoded-key (pgp/encode-ascii decoded-key)))))
