(defproject mvxcvi/clj-pgp "0.5.4"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :dependencies
  [[byte-streams "0.1.13"]
   [potemkin "0.3.9"]
   [org.bouncycastle/bcpg-jdk15on "1.51"]
   [org.clojure/clojure "1.6.0"]]

  :hiera
  {:cluster-depth 3}

  :profiles
  {:coverage
   {:plugins
    [[lein-cloverage "1.0.2"]]}})
