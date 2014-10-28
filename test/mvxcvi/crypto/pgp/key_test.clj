(ns mvxcvi.crypto.pgp.key-test
  (:require
    [midje.sweet :refer :all]
    [mvxcvi.crypto.pgp :as pgp]
    [mvxcvi.crypto.pgp.test-keys :as test-keys :refer [pubkey seckey privkey]])
  (:import
    (org.bouncycastle.openpgp
      PGPPrivateKey
      PGPPublicKey
      PGPSecretKey)))


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
  (fact "secret keyrings give first public key"
    (pgp/public-key test-keys/secring) => (partial instance? PGPPublicKey))
  (fact "public keys return themselves"
    (pgp/public-key pubkey) => pubkey))


(facts "secret-key coercion"
    (fact "secret keyrings give first secret key"
      (pgp/secret-key test-keys/secring) => (partial instance? PGPSecretKey))
    (fact "secret keys return themselves"
      (pgp/secret-key seckey) => seckey))


(facts "secret-key unlocking"
  (fact "secret keys unlock into private keys"
    privkey => (partial instance? PGPPrivateKey))
  (fact "unlocking with the wrong password throws an exception"
    (pgp/unlock-key seckey "wrong password") => (throws Exception)))


(facts "key-info"
  (fact
    (pgp/key-info test-keys/master-pubkey)
    => (contains {:key-id -7909697412827827830
                  :fingerprint "4C0F256D432975418FAB3D7B923B1C1C4392318A"
                  :algorithm :rsa-general
                  :strength 1024
                  :master-key? true
                  :encryption-key? true
                  :user-ids ["Test User <test@vault.mvxcvi.com>"]}))
  (fact
    (pgp/key-info seckey)
    => (contains {:key-id 4557904421870553981
                  :fingerprint "798A598943062D6C0D1D40F73F40EDEC41C6CB7D"
                  :algorithm :rsa-general
                  :strength 1024
                  :master-key? false
                  :secret-key? true
                  :encryption-key? true
                  :signing-key? true})))
