(ns clj-pgp.generate
  "This namespace provides functionality to generate PGP keypairs and keyrings
  using a convenient macro syntax.

  The two primary supported key types are RSA keys (via `rsa-keypair-generator`)
  and Elliptic Curve keys (via `ec-keypair-generator`). A set of the supported
  named curves can be found in `elliptic-curve-names`.

  To generate PGP keyrings with designater master keys and subkeys with specific
  roles and restrictions, use the `generate-keys` macro. This returns a map with
  `:public` and `:secret` entries containing the respective keyrings."
  (:require
    [clj-pgp.core :as pgp]
    [clj-pgp.tags :as tags]
    [clj-pgp.util :refer [arg-seq]]
    [clojure.string :as str])
  (:import
    java.security.SecureRandom
    java.util.Date
    (org.bouncycastle.asn1.sec
      SECNamedCurves)
    (org.bouncycastle.asn1.x9
      X9ECParameters)
    (org.bouncycastle.bcpg.sig
      Features
      KeyFlags)
    (org.bouncycastle.crypto
      AsymmetricCipherKeyPairGenerator)
    (org.bouncycastle.crypto.generators
      ECKeyPairGenerator
      RSAKeyPairGenerator)
    (org.bouncycastle.crypto.params
      ECKeyGenerationParameters
      ECNamedDomainParameters
      RSAKeyGenerationParameters)
    (org.bouncycastle.openpgp
      PGPKeyPair
      PGPKeyRingGenerator
      PGPSignature
      PGPSignatureSubpacketGenerator)
    (org.bouncycastle.openpgp.operator
      PGPDigestCalculator)
    (org.bouncycastle.openpgp.operator.bc
      BcPBESecretKeyEncryptorBuilder
      BcPGPContentSignerBuilder
      BcPGPDigestCalculatorProvider
      BcPGPKeyPair)))


;; ## KeyPair Generation

(defn generate-keypair
  "Builds a new PGP keypair from a generator."
  ^PGPKeyPair
  [^AsymmetricCipherKeyPairGenerator generator
   algorithm]
  (BcPGPKeyPair.
    (tags/public-key-algorithm-code algorithm)
    (.generateKeyPair generator)
    (Date.)))


(defn rsa-keypair-generator
  "Constructs a new generator for RSA keypairs with the given bit strength.
  Other parameters may be customized with keyword options.

  Opts may include:

  - `:random` a custom random number generator
  - `:exponent` RSA algorithm public exponent
  - `:certainty` threshold for probabilistic prime generation"
  {:arglists '([strength & opts])}
  ^RSAKeyPairGenerator
  [strength & {:keys [random exponent certainty]
               :or {random (SecureRandom/getInstance "SHA1PRNG")
                    exponent (BigInteger/valueOf 0x10001)
                    certainty 80}}]
  (doto (RSAKeyPairGenerator.)
    (.init (RSAKeyGenerationParameters.
             exponent
             random
             strength
             certainty))))


(def elliptic-curve-names
  "Set of supported elliptic curves."
  (set (iterator-seq (SECNamedCurves/getNames))))


(defn ec-keypair-generator
  "Constructs a new generator for keypairs on the named elliptic curve.

  Opts may include:

  - `:random` a custom random number generator"
  {:arglists '([curve & opts])}
  [curve
   & {:keys [^SecureRandom random]
      :or {random (SecureRandom/getInstance "SHA1PRNG")}}]
  (let [^X9ECParameters params (SECNamedCurves/getByName curve)]
    (doto (ECKeyPairGenerator.)
      (.init (ECKeyGenerationParameters.
               (ECNamedDomainParameters.
                 (SECNamedCurves/getOID curve)
                 (.getCurve params)
                 (.getG params)
                 (.getN params)
                 (.getH params)
                 (.getSeed params))
               random)))))



;; ## Key Signatures

(defn signature-subpacket-generator
  "Constructs a new generator for key signature subpackets. The given flags
  will be applied to the key."
  ^PGPSignatureSubpacketGenerator
  [& flags]
  (let [generator (PGPSignatureSubpacketGenerator.)]
    (when (seq flags)
      (.setKeyFlags generator false (if (< 1 (count flags))
                                      (apply bit-or flags)
                                      (first flags))))
    generator))


(defn signature-generator
  "Constructs a signature subpacket generator with a preset mode. This can be
  one of `:master`, `:signing`, or `:encryption`."
  [mode]
  (case mode
    :master
    (doto (signature-subpacket-generator
            KeyFlags/SIGN_DATA
            KeyFlags/CERTIFY_OTHER)
      ; Request senders add additional checksums to the message (useful
      ; when verifying unsigned messages).
      (.setFeature false Features/FEATURE_MODIFICATION_DETECTION))

    :signing
    (signature-subpacket-generator
      KeyFlags/ENCRYPT_COMMS
      KeyFlags/ENCRYPT_STORAGE)

    :encryption
    (signature-subpacket-generator
      KeyFlags/SIGN_DATA)))


(defmacro ^:private defpreference
  "Builds a function which sets preferences on a signature generator for
  secondary cryptographic algorithms to prefer."
  [pref-type tag->code]
  `(defn ~(symbol (str "prefer-" (str/lower-case pref-type) "-algorithms!"))
     "Sets the list of preferred algorithms on a signature generator for
     use when sending messages to the key."
     [generator# & algorithms#]
     (when-let [prefs# (arg-seq algorithms#)]
       (~(symbol (str ".setPreferred" pref-type "Algorithms"))
        ^PGPSignatureSubpacketGenerator generator#
        false
        (int-array (map ~tag->code prefs#))))))


(defpreference Symmetric   tags/symmetric-key-algorithm-code)
(defpreference Hash        tags/hash-algorithm-code)
(defpreference Compression tags/compression-algorithm-code)


(defn set-key-expiration!
  "Sets a key expiration time on a signature generator. The lifetime is
  expressed as a number of seconds since the key creation time."
  [^PGPSignatureSubpacketGenerator generator
   ^long lifetime]
  (.setKeyExpirationTime generator true lifetime))



;; ## Keyring Construction

(defn- digest-calculator
  "Constructs a new digest calculator for the given hash algorithm."
  ^PGPDigestCalculator
  [algorithm]
  (.get (BcPGPDigestCalculatorProvider.)
        (tags/hash-algorithm-code algorithm)))


(defn- secret-key-encryptor
  "Constructs a new encryptor which will lock secret keys with the given
  passphrase. The encryption algorithm and passphrase hash algorithm may be
  specified as optional keyword arguments."
  [^String passphrase
   & {:keys [enc-algo pass-algo]
      :or {enc-algo :aes-256
           pass-algo :sha256}}]
  (.build (BcPBESecretKeyEncryptorBuilder.
            (tags/symmetric-key-algorithm-code enc-algo)
            (digest-calculator pass-algo))
          (.toCharArray passphrase)))


(defn keyring-generator
  "Constructs a new generator for a keyring for a user-id, encrypted with the
  given passphrase. The provided keypair will become the master key with any
  options specified in the signature subpacket."
  [^String user-id
   ^String passphrase
   ^PGPKeyPair master-key
   ^PGPSignatureSubpacketGenerator master-sig-gen]
  (PGPKeyRingGenerator.
    PGPSignature/POSITIVE_CERTIFICATION
    master-key
    user-id
    (digest-calculator :sha1)
    (.generate master-sig-gen)
    nil
    (BcPGPContentSignerBuilder.
      (tags/public-key-algorithm-code (pgp/key-algorithm master-key))
      (tags/hash-algorithm-code :sha1))
    (secret-key-encryptor passphrase)))


(defn add-subkey!
  "Adds a subkey and signature packet to a keyring genrator."
  [^PGPKeyRingGenerator generator
   ^PGPKeyPair subkey
   ^PGPSignatureSubpacketGenerator sig-gen]
  (.addSubKey generator subkey (.generate sig-gen) nil))


(defn generate-keyrings
  "Generates both the public and secret keyrings from the given generator."
  [^PGPKeyRingGenerator keyring-gen]
  {:public (.generatePublicKeyRing keyring-gen)
   :secret (.generateSecretKeyRing keyring-gen)})



;; ## Keyring Specification

(defn- group-key-spec
  "Checks a single key specification, updating the map with either a master-key
  or subkey entry."
  [spec-map spec]
  (when-not (list? spec)
    (throw (IllegalArgumentException.
             (str "Key specifications must be lists: " spec))))
  (if (= 'master-key (first spec))
    (if (:master spec-map)
      (throw (IllegalArgumentException.
               (str "Cannot specify multiple master-key specs: " spec)))
      (assoc spec-map :master spec))
    (update-in spec-map [:subkeys] conj spec)))


(defn- subpacket->fn
  [packet]
  (when-not (list? packet)
    (throw (IllegalArgumentException.
             (str "Signature subpacket forms must be lists: " packet))))
  (let [fns {'prefer-symmetric   `prefer-symmetric-algorithms!
             'prefer-hash        `prefer-hash-algorithms!
             'prefer-compression `prefer-compression-algorithms!
             'expires            `set-key-expiration!}
        [packet-type & args] packet]
    (when-not (contains? fns packet-type)
      (throw (IllegalArgumentException.
               (str "Unknown signature subpacket type: " packet-type))))
    (cons (fns packet-type) args)))


(defn- keypair-with-signature-subpackets
  "Standard form to create a list of keypair with a doto block around the
  signature generator to apply the subpackets."
  [sig-generator keypair sig-subpackets]
  [(if (and (list? keypair) (= 'keypair (first keypair)))
     (cons `generate-keypair (rest keypair))
     keypair)
   (if (seq sig-subpackets)
     `(doto ~sig-generator
        ~@(map subpacket->fn sig-subpackets))
     sig-generator)])


(defn- master-keyring-generator
  [user-id passphrase key-spec]
  (let [[keypair & sig-subpackets] (rest key-spec)]
    `(keyring-generator
       ~user-id ~passphrase
       ~@(keypair-with-signature-subpackets
           `(signature-generator :master)
           keypair
           sig-subpackets))))


(defn- add-keyring-subkey
  [[key-type keypair & sig-subpackets]]
  (cons
    `add-subkey!
    (keypair-with-signature-subpackets
      (case key-type
        encryption-key `(signature-generator :encryption)
        signing-key    `(signature-generator :signing)
        (throw (IllegalArgumentException.
                 (str "Unknown subkey type " key-type))))
      keypair
      sig-subpackets)))


(defmacro generate-keys
  "Macro to generate keys with a mini-language to specify preferences and
  subkeys.

  An example invocation that creates a master key with signing and encryption
  subkeys:

  ```
  (pgp-gen/generate-keys
    \"test user\" \"test passphrase\"
    (master-key
      (keypair rsa :rsa-general)
      (prefer-symmetric :aes-256 :aes-128)
      (prefer-hash :sha512 :sha256 :sha1)
      (prefer-compression :zlib :bzip2))
    (signing-key
      (keypair rsa :rsa-general)
      (expires 36000))
    (encryption-key
      (keypair rsa :rsa-general)))
  ```"
  [user-id passphrase & key-specs]
  (let [spec-map (reduce group-key-spec {:subkeys []} key-specs)]
    (when-not (:master spec-map)
      (throw (IllegalArgumentException.
               (str "No master-key specification provided in key-specs: " key-specs))))
    `(generate-keyrings
       (doto
         ~(master-keyring-generator user-id passphrase (:master spec-map))
         ~@(map add-keyring-subkey (:subkeys spec-map))))))
