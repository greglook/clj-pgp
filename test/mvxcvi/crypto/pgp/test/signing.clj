(ns mvxcvi.crypto.pgp.test.signing
  (:require
    [clojure.test.check :as check]
    [clojure.test.check.generators :as gen]
    [clojure.test.check.properties :as prop]
    [byte-streams :refer [bytes=]]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    (mvxcvi.crypto.pgp
      [generate :as pgp-gen]
      [tags :as tags])
    [mvxcvi.crypto.pgp.test.keys :refer
     [master-pubkey pubkey privkey spec->keypair gen-rsa-keyspec]]))


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



;; ## Generative Checks

(defn test-signing-keypair
  "Tests that signing data with the given keypair results in a verifiable
  signature."
  [keyspec data hash-algo]
  (facts (str "Keypair " (pr-str keyspec) " signing "
              (count data) " bytes with " hash-algo)
    (let [keypair (spec->keypair keyspec)
          sig (pgp/sign data keypair hash-algo)]
      (fact "signature key-id matches key"
        (pgp/key-id sig) => (pgp/key-id keypair))
      (fact "verification with the wrong public key throws error"
        (pgp/verify data sig pubkey)
        => (throws IllegalArgumentException))
      (fact "verification with public key succeeds"
        (pgp/verify data sig keypair) => true)
      (let [binary (pgp/encode sig)
            sig' (pgp/decode-signature binary)]
        (fact "binary representation is canonical"
          (pgp/encode sig') => (partial bytes= binary))
        (fact "decoded signature can be verified"
          (pgp/verify data sig' keypair) => true)))))


(def keypair-signing-property
  (prop/for-all*
    [(gen-rsa-keyspec [:rsa-sign :rsa-general] [1024 2048])
     gen/bytes
     (gen/elements [:md5 :sha1 :sha256 :sha512])]
    test-signing-keypair))


(facts "Generative signature testing"
  (test-signing-keypair
    [:rsa :rsa-sign 1024]
    "Important message!"
    :sha1)
  (test-signing-keypair
    [:rsa :rsa-sign 2048]
    "Hello, world!"
    :sha256)
  (test-signing-keypair
    [:rsa :rsa-general 4096]
    "This needs protection"
    :sha512))
