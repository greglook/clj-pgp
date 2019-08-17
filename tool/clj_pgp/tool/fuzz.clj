(ns clj-pgp.tool.fuzz
  (:gen-class)
  (:require
    [clj-pgp.test.encryption :refer [data-encryption-property]]
    [clj-pgp.test.signing :refer [keypair-signing-property]]
    [clojure.test.check :as check]
    [puget.printer :as puget]))


(def ^:private check-templates
  [["public-key data encryption" data-encryption-property]
   ["public-key data signatures" keypair-signing-property]])


(defn- batch-jobs
  "Constructs a number of batches of check jobs, each running n iterations."
  [batches n]
  (reduce (fn [q b]
            (into q (map #(concat % [b n])
                         check-templates)))
          [] (range batches)))


(defn- check-property
  "Checks a property `n` times, then reports the results."
  [title prop batch n]
  (let [start (System/currentTimeMillis)
        result (check/quick-check n prop)
        elapsed (- (System/currentTimeMillis) start)]
    (assoc result
           :title title
           :batch batch
           :elapsed elapsed)))


(defn- report-checks
  "Reports the results of running property checks by printing stats to
  the output stream."
  [result]
  (printf
    "\n%s (%.3f sec @ %.1f cps)\n%s\n"
    (:title result)
    (/ (:elapsed result) 1000.0)
    (/ (:num-tests result) (:elapsed result) 0.001)
    (puget/cprint-str (dissoc result :title :elapsed)))
  (when (instance? Throwable (:result result))
    (.printStackTrace ^Throwable (:result result)))
  (flush))


(defn -main
  "Runs generative property checks on the library code. Accepts two arguments:
  - `n` the number of checks to run in each batch (default: 10)
  - `batches` the number of batches to run (default: 1)

  Each batch runs `n` checks on each generative test property. Each property is
  tested on a separate thread."
  [& [n batches]]
  (let [n (if n (Integer/parseInt n) 10)
        batches (if batches (Integer/parseInt batches) 1)
        check-jobs (batch-jobs batches n)]
    (println "Running" (count check-templates) "property checks in" batches "batches of" n "iterations")
    (flush)
    (doseq [result (pmap (partial apply check-property) check-jobs)]
      (report-checks result)
      (when-not (true? (:result result))
        (println "\nGenerative tests failed!")
        (System/exit 1)))
    (shutdown-agents)))
