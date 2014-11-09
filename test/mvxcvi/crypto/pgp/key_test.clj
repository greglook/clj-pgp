(ns mvxcvi.crypto.pgp.key-test
  (:require
    [byte-streams :refer [bytes=]]
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as test-keys
     :refer [privkey pubkey pubring seckey secring]])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)))


(facts "keyrings"
  (fact "public keyring contains two public keys"
    (pgp/list-public-keys pubring) => (two-of (partial instance? PGPPublicKey)))
  (fact "secret keyring contains two keypairs"
    (pgp/list-public-keys secring) => (two-of (partial instance? PGPPublicKey))
    (pgp/list-secret-keys secring) => (two-of (partial instance? PGPSecretKey))))


(facts "key-id coercion"
  (fact "nil returns nil"
    (pgp/key-id nil) => nil)
  (fact "longs return value"
    (pgp/key-id 1234) => 1234)
  (fact "hex strings return numeric value"
    (pgp/key-id "923b1c1c4392318a") => -7909697412827827830
    (pgp/key-id "3f40edec41c6cb7d") =>  4557904421870553981)
  (fact "key ids match"
    (pgp/key-id pubkey)  => 4557904421870553981
    (pgp/key-id seckey)  => 4557904421870553981
    (pgp/key-id privkey) => 4557904421870553981))


(facts "hex key-id"
  (fact "nil returns nil"
    (pgp/hex-id nil) => nil)
  (fact "longs returns hex"
    (pgp/hex-id 4557904421870553981) => "3f40edec41c6cb7d"))


(facts "hex fingerprints"
  (fact "nil returns nil"
    (pgp/hex-fingerprint nil) => nil)
  (fact "keys return hex strings"
    (pgp/hex-fingerprint seckey) => "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"))


(facts "key-algorithm coercion"
  (fact "nil returns nil"
    (pgp/key-algorithm nil) => nil)
  (fact "keywords return value"
    (pgp/key-algorithm :rsa-general) => :rsa-general)
  (fact "keys return keyword values"
    (pgp/key-algorithm pubkey)  => :rsa-general
    (pgp/key-algorithm seckey)  => :rsa-general
    (pgp/key-algorithm privkey) => :rsa-general))


(facts "public-key coercion"
  (fact "nil returns nil"
    (pgp/public-key nil) => nil)
  (fact "public keys return themselves"
    (pgp/public-key pubkey) => pubkey))


(facts "secret-key unlocking"
  (fact "secret keys unlock into private keys"
    privkey => (partial instance? PGPPrivateKey))
  (fact "unlocking with the wrong password throws an exception"
    (pgp/unlock-key seckey "wrong password") => (throws Exception)))


(facts "key-info"
  (fact "nil returns nil"
    (pgp/key-info nil) => nil)
  (fact "keys return a map of attributes"
    (pgp/key-info test-keys/master-pubkey)
    => (contains {:key-id "923b1c1c4392318a"
                  :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A"
                  :algorithm :rsa-general
                  :strength 1024
                  :master-key? true
                  :encryption-key? true
                  :user-ids ["Test User <test@vault.mvxcvi.com>"]})
    (pgp/key-info seckey)
    => (contains {:key-id "3f40edec41c6cb7d"
                  :fingerprint "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
                  :algorithm :rsa-general
                  :strength 1024
                  :master-key? false
                  :secret-key? true
                  :encryption-key? true
                  :signing-key? true})))


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
