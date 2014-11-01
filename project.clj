(defproject mvxcvi/clj-pgp "0.6.0-SNAPSHOT"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :aliases {"docs" ["do" ["doc"] ["marg" "--multi" "--dir" "target/doc/marginalia"] ["hiera"]]
            "tests" ["do" ["check"] ["test"] ["cloverage"]]}

  :plugins [[codox "0.8.10"]
            [lein-cloverage "1.0.2"]
            [lein-marginalia "0.8.0"]]

  :dependencies [[byte-streams "0.1.13"]
                 [potemkin "0.3.11"]
                 [org.bouncycastle/bcpg-jdk15on "1.51"]]

  :hiera {:path "target/doc/ns-hiera.png"
          :cluster-depth 3}

  :codox {:defaults {:doc/format :markdown}
          :output-dir "target/doc/api"
          :src-dir-uri "https://github.com/greglook/clj-pgp/blob/master/"
          :src-linenum-anchor-prefix "L"}

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.6.0"]]}
             :test {:dependencies [[midje "1.6.3"]]}})
