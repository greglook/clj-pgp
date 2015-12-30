(defproject mvxcvi/clj-pgp "0.8.3"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :aliases {"doc-lit" ["marg" "--multi" "--dir" "doc/marginalia"]
            "fuzz" ["with-profile" "+tool" "run" "-m" "clj-pgp.tool.fuzz"]}

  :plugins
  [[lein-cloverage "1.0.2"]]

  :dependencies
  [[byte-streams "0.2.0"]
   [org.bouncycastle/bcpg-jdk15on "1.54"]
   [org.bouncycastle/bcprov-jdk15on "1.54"]]

  :hiera {:cluster-depth 1}

  :codox {:exclude #{clj-pgp.tags clj-pgp.util}
          :src-dir-uri "https://github.com/greglook/clj-pgp/blob/master/"}

  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/clojure "1.7.0"]
                                  [org.clojure/test.check "0.9.0"]
                                  [org.clojure/tools.namespace "0.2.10"]]}

             :tool {:source-paths ["tool"]
                    :dependencies [[mvxcvi/puget "1.0.0"]
                                   [org.clojure/core.async "0.2.374"]]
                    :jvm-opts []}})
