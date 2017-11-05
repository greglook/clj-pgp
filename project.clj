(defproject mvxcvi/clj-pgp "0.9.1-SNAPSHOT"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :aliases
  {"doc-lit" ["marg" "--multi" "--dir" "doc/marginalia"]
   "coverage" ["with-profile" "+coverage" "cloverage"]
   "fuzz" ["with-profile" "+tool" "run" "-m" "clj-pgp.tool.fuzz"]}

  :deploy-branches ["master"]
  :pedantic? :abort

  :dependencies
  [[org.clojure/clojure "1.8.0" :scope "provided"]
   [org.bouncycastle/bcpg-jdk15on "1.58"]
   [org.bouncycastle/bcprov-jdk15on "1.58"]
   [byte-streams "0.2.3"]]

  :hiera
  {:cluster-depth 1}

  :codox
  {:metadata {:doc/format :markdown}
   :exclude #{clj-pgp.tags clj-pgp.util}
   :source-uri "https://github.com/greglook/clj-pgp/blob/master/"
   :output-path "target/doc/api"}

  :profiles
  {:repl
   {:source-paths ["dev"]
    :dependencies
    [[org.clojure/test.check "0.9.0"]
     [org.clojure/tools.namespace "0.2.11"]]}

   :tool
   {:source-paths ["tool"]
    :dependencies [[mvxcvi/puget "1.0.2"]]
    :jvm-opts []}

   :coverage
   {:plugins [[lein-cloverage "1.0.10"]]
    :dependencies [[riddley "0.1.14"]]} })
