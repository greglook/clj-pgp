(ns clj-pgp.test.signing
  (:require
    [byte-streams :refer [bytes=]]
    [clj-pgp.core :as pgp]
    [clj-pgp.generate :as pgp-gen]
    [clj-pgp.signature :as pgp-sig]
    [clj-pgp.test.keys :refer
     [master-pubkey pubkey privkey
      gen-ec-keyspec
      gen-rsa-keyspec
      memospec->keypair]]
    [clojure.test :refer [deftest testing is]]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]))


(deftest signature-verification
  (let [data "cryptography is neat"
        sig (pgp-sig/sign data privkey)]
    (is (= (pgp/key-id privkey) (pgp/key-id sig))
        "signature key-id matches key")
    (is (thrown? IllegalArgumentException
          (pgp-sig/verify data sig master-pubkey))
        "verification with the wrong public key throws error")
    (is (pgp-sig/verify data sig pubkey)
        "verification with public key succeeds")))


(deftest signature-encoding
  (let [data "very important data to trust"
        sig (pgp-sig/sign data privkey)
        binary (pgp/encode sig)
        [sig'] (pgp/decode-signatures binary)]
    (is (bytes= binary (pgp/encode sig'))
        "binary representation is canonical")
    (is (pgp-sig/verify data sig' pubkey)
        "decoded signature can be verified")
    (is (thrown? IllegalArgumentException
          (pgp/decode-signatures (pgp/encode pubkey)))
        "decoding non-signature value throws an exception")))



;; ## Generative Checks

(defn test-signing-keypair
  "Tests that signing data with the given keypair results in a verifiable
  signature."
  [keyspec data hash-algo]
  (testing (str "Keypair " (pr-str keyspec) " signing "
                (count data) " bytes with " hash-algo)
    (let [keypair (memospec->keypair keyspec)
          sig (pgp-sig/sign data keypair :hash-algo hash-algo)]
      (is (= (pgp/key-id keypair) (pgp/key-id sig))
          "signature key-id matches key")
      (is (thrown? IllegalArgumentException
            (pgp-sig/verify data sig pubkey))
          "verification with the wrong public key throws error")
      (is (pgp-sig/verify data sig keypair)
          "verification with public key succeeds")
      (let [binary (pgp/encode sig)
            [sig'] (pgp/decode-signatures binary)]
        (is (bytes= binary (pgp/encode sig'))
            "binary representation is canonical")
        (is (pgp-sig/verify data sig' keypair)
            "decoded signature can be verified")))))


(def keypair-signing-property
  (prop/for-all*
    [(gen/one-of
       [(gen-rsa-keyspec [1024 2048 4096])
        (gen-ec-keyspec :ecdsa pgp-gen/elliptic-curve-names)])
     (gen/not-empty gen/bytes)
     (gen/elements [:md5 :sha1 :sha256 :sha512])]
    test-signing-keypair))


(deftest data-signatures
  (test-signing-keypair
    [:rsa :rsa-sign 1024]
    "Important message!"
    :sha1)
  (test-signing-keypair
    [:rsa :rsa-general 2048]
    "Hello, world!"
    :sha256)
  (test-signing-keypair
    [:rsa :rsa-general 4096]
    "This needs protection"
    :sha512))
