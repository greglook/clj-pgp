(defproject mvxcvi/clj-pgp "1.1.2-SNAPSHOT"
  :description "Wrapper for the Bouncy Castle OpenPGP library"
  :url "https://github.com/greglook/clj-pgp"
  :license {:name "Public Domain"
            :url "http://unlicense.org/"}

  :aliases
  {"coverage" ["with-profile" "+coverage" "cloverage"]
   "fuzz" ["with-profile" "+tool" "run" "-m" "clj-pgp.tool.fuzz"]}

  :deploy-branches ["main"]
  :pedantic? :abort

  :dependencies
  [[org.clojure/clojure "1.12.0" :scope "provided"]
   [org.bouncycastle/bcpg-jdk18on "1.79"]
   [org.bouncycastle/bcprov-jdk18on "1.79"]
   [org.clj-commons/byte-streams "0.3.4"]]

  :hiera
  {:cluster-depth 1}

  :profiles
  {:dev
   {:dependencies [[org.clojure/test.check "1.1.1"]]}

   :repl
   {:source-paths ["dev"]
    :dependencies [[org.clojure/tools.namespace "1.5.0"]]}

   :coverage
   {:plugins [[lein-cloverage "1.2.2"]]
    :dependencies [[org.clojure/tools.logging "1.3.0"]]}

   :tool
   {:source-paths ["tool"]
    :dependencies [[mvxcvi/puget "1.3.4"]]
    :jvm-opts []}})
