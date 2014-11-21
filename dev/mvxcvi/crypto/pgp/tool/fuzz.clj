(ns mvxcvi.crypto.pgp.tool.fuzz
  (:require
    [clojure.test.check :as check]
    (mvxcvi.crypto.pgp.test
      [encryption :refer [keypair-encryption-property]]
      [signing :refer [keypair-signing-property]])
    [puget.printer :as puget])
  (:gen-class))


(def ^:private results-agent
  "An agent to serialize writing to an output stream. Stores all results
  reported so far."
  (agent []))


(defn- report-checks
  [results title result]
  (printf
    "\n%s (%.3f sec @ %.1f cps)\n%s\n"
    title
    (/ (:elapsed result) 1000.0)
    (/ (:num-tests result) (:elapsed result) 0.001)
    (puget/cprint-str result))
  (conj results result))


(defn- check-property
  "Checks a property `n` times, then reports the results."
  [title prop batch n]
  (let [start (System/currentTimeMillis)
        result (check/quick-check n prop)
        elapsed (- (System/currentTimeMillis) start)]
    (send results-agent report-checks title
          (assoc result
            :batch batch
            :elapsed elapsed))
    (delay (await results-agent)
           (:result result))))


(defn -main
  "Runs generative property checks on the library code. Accepts two arguments:
  - `n` the number of checks to run in each batch (default: 10)
  - `batches` the number of batches to run (default: 1)

  Each batch runs `n` checks on each generative test property. Each property is
  tested on a separate thread."
  [& [n batches]]
  (let [n (if n (Integer/parseInt n) 10)
        batches (if batches (Integer/parseInt batches) 1)
        templates [["public-key data encryption" keypair-encryption-property]
                   ["public-key data signatures" keypair-signing-property]]]
    (println "Running" (count templates) "property checks in" batches "batches of" n "iterations")
    (let [checks (reduce
                   (fn [q b]
                     (into q (map #(concat % [b n]) templates)))
                   [] (range batches))
          results (apply pmap check-property (apply mapv vector checks))]
      (when-not (every? (comp true? deref) results)
        (println "\nGenerative tests failed!")
        (System/exit 1)))
    (shutdown-agents)))
