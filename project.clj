(defproject mvxcvi/clj-pgp "0.5.0"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :dependencies
  [[byte-streams "0.1.6"]
   [potemkin "0.3.4"]
   [org.bouncycastle/bcpg-jdk15on "1.49"]
   [org.clojure/clojure "1.5.1"]]

  :hiera
  {:cluster-depth 3})
