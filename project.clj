(defproject mvxcvi/clj-pgp "0.8.0"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :aliases {"docs" ["do" ["hiera"] ["doc"] ["marg" "--multi" "--dir" "doc/marginalia"]]
            "tests" ["do" ["check"] ["test"] ["cloverage"]]
            "fuzz" ["with-profile" "+tool" "run" "-m" "clj-pgp.tool.fuzz"]}

  :plugins [[codox "0.8.10"]
            [lein-cloverage "1.0.2"]
            [lein-marginalia "0.8.0"]]

  :dependencies [[byte-streams "0.1.13"]
                 [org.bouncycastle/bcpg-jdk15on "1.51"]
                 [org.bouncycastle/bcprov-jdk15on "1.51"]]

  :hiera {:path "doc/ns-hiera.png"
          :cluster-depth 1
          :ignore-ns #{user}}

  :codox {:defaults {:doc/format :markdown}
          :exclude #{user clj-pgp.tags clj-pgp.util}
          :output-dir "doc/api"
          :src-dir-uri "https://github.com/greglook/clj-pgp/blob/master/"
          :src-linenum-anchor-prefix "L"}

  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/clojure "1.6.0"]
                                  [org.clojure/test.check "0.6.1"]
                                  [org.clojure/tools.namespace "0.2.7"]]}

             :tool {:source-paths ["tool"]
                    :dependencies [[mvxcvi/puget "0.6.4"]
                                   [org.clojure/core.async "0.1.303.0-886421-alpha"]]
                    :jvm-opts []}})
