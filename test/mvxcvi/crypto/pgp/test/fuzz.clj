(ns mvxcvi.crypto.pgp.test.fuzz
  (:require
    [clojure.test.check :as check]
    (mvxcvi.crypto.pgp.test
      [encryption :refer [keypair-encryption-property]]))
  (:gen-class))


(defn -main
  [& [n]]
  (let [n (Integer/parseInt (or n 10))]
    (println "Running property checks for" n "iterations")
    (let [kep (future (check/quick-check n keypair-encryption-property))]
      (println "Keypair Encryption:" (pr-str @kep))
      (when-not (every? true? (map :result [@kep]))
        (println "Generative tests failed!")
        (System/exit 1))
      (shutdown-agents))))
