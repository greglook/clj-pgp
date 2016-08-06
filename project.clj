(defproject mvxcvi/clj-pgp "0.9.0-SNAPSHOT"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :deploy-branches ["master"]

  :aliases {"doc-lit" ["marg" "--multi" "--dir" "doc/marginalia"]
            "fuzz" ["with-profile" "+tool" "run" "-m" "clj-pgp.tool.fuzz"]}

  :plugins
  [[lein-cloverage "1.0.6"]]

  :dependencies
  [[org.clojure/clojure "1.8.0" :scope "provided"]
   [org.bouncycastle/bcpg-jdk15on "1.54"]
   [org.bouncycastle/bcprov-jdk15on "1.54"]
   [byte-streams "0.2.2"]]

  :hiera
  {:cluster-depth 1}

  :codox
  {:exclude #{clj-pgp.tags clj-pgp.util}
   :src-dir-uri "https://github.com/greglook/clj-pgp/blob/master/"}

  :profiles
  {:dev
   {:source-paths ["dev"]
    :dependencies [[org.clojure/test.check "0.9.0"]
                   [org.clojure/tools.namespace "0.2.10"]]}

   :tool
   {:source-paths ["tool"]
    :dependencies [[mvxcvi/puget "1.0.0"]]
    :jvm-opts []}})
