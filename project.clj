(defproject mvxcvi/clj-pgp "0.10.2"
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
  [[org.clojure/clojure "1.10.1" :scope "provided"]
   [org.bouncycastle/bcpg-jdk15on "1.65"]
   [org.bouncycastle/bcprov-jdk15on "1.65"]
   [byte-streams "0.2.4"]]

  :hiera
  {:cluster-depth 1}

  :codox
  {:metadata {:doc/format :markdown}
   :exclude #{clj-pgp.tags clj-pgp.util}
   :source-uri "https://github.com/greglook/clj-pgp/blob/master/"
   :output-path "target/doc/api"}

  :profiles
  {:dev
   {:dependencies [[org.clojure/test.check "1.0.0"]]}

   :repl
   {:source-paths ["dev"]
    :dependencies [[org.clojure/tools.namespace "1.0.0"]]}

   :coverage
   {:plugins [[lein-cloverage "1.1.0"]]}

   :tool
   {:source-paths ["tool"]
    :dependencies [[mvxcvi/puget "1.2.1"]]
    :jvm-opts []}})
