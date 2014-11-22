(ns mvxcvi.crypto.pgp.tool.fuzz
  (:require
    [clojure.core.async :as async :refer [<! >! <!!]]
    [clojure.test.check :as check]
    (mvxcvi.crypto.pgp.test
      [encryption :refer [keypair-encryption-property]]
      [signing :refer [keypair-signing-property]])
    [puget.printer :as puget])
  (:gen-class))


(def ^:private check-templates
  [["public-key data encryption" keypair-encryption-property]
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
  [result]
  (printf
    "\n%s (%.3f sec @ %.1f cps)\n%s\n"
    (:title result)
    (/ (:elapsed result) 1000.0)
    (/ (:num-tests result) (:elapsed result) 0.001)
    (puget/cprint-str (dissoc result :title :elapsed)))
  (when (instance? Throwable (:result result))
    (.printStackTrace (:result result))))


(defn -main
  "Runs generative property checks on the library code. Accepts two arguments:
  - `n` the number of checks to run in each batch (default: 10)
  - `batches` the number of batches to run (default: 1)

  Each batch runs `n` checks on each generative test property. Each property is
  tested on a separate thread."
  [& [n batches parallelism]]
  (let [n (if n (Integer/parseInt n) 10)
        batches (if batches (Integer/parseInt batches) 1)
        parallelism (if parallelism (Integer/parseInt parallelism) 4)
        checks (batch-jobs batches n)
        job-queue (async/to-chan checks)
        results (async/chan)]
    (println "Running" (count check-templates) "property checks in" batches "batches of" n "iterations across" parallelism "threads")
    (let [workers
          (for [i (range parallelism)]
            (async/go-loop []
              (if-let [job (<! job-queue)]
                (do
                  (>! results (apply check-property job))
                  (recur))
                (>! results ::finish))))
          reporter
          (async/go-loop [active-workers parallelism]
            (when (pos? active-workers)
              (when-let [result (<! results)]
                (if (= result ::finish)
                  (recur (dec active-workers))
                  (do
                    (report-checks result)
                    (when-not (true? (:result result))
                      (println "\nGenerative tests failed!")
                      (System/exit 1))
                    (recur active-workers))))))]
      ; Wait for workers to exit.
      (doseq [w workers] (<!! w))
      ; Wait for reporter to close on receiving ::finish signals.
      (<!! reporter)
      (async/close! results))
    (shutdown-agents)))
