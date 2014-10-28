(defproject mvxcvi/clj-pgp "0.6.0-SNAPSHOT"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :dependencies [[byte-streams "0.1.13"]
                 [org.bouncycastle/bcpg-jdk15on "1.51"]
                 [org.bouncycastle/bcprov-jdk15on "1.51"]
                 [potemkin "0.3.11"]]

  :hiera {:cluster-depth 3}

  :profiles {:dev {:plugins [[lein-cloverage "1.0.2"]]
                   :dependencies [[midje "1.6.3"]
                                  [org.clojure/clojure "1.6.0"]]}})
