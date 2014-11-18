(ns mvxcvi.crypto.pgp.test.fuzz
  (:require
    [clojure.test.check :as check]
    (mvxcvi.crypto.pgp.test
      [encryption :refer [keypair-encryption-property]]
      [signing :refer [keypair-signing-property]]))
  (:gen-class))


(defn -main
  [& [n]]
  (let [n (Integer/parseInt (or n 10))]
    (println "Running property checks for" n "iterations")
    (let [kep (future (check/quick-check n keypair-encryption-property))
          ksp (future (check/quick-check n keypair-signing-property))]
      (println "Keypair encryption:" (pr-str @kep))
      (println "Keypair signatures:" (pr-str @ksp))
      (when-not (every? true? (map (comp :result deref) [kep ksp]))
        (println "Generative tests failed!")
        (System/exit 1))
      (shutdown-agents))))
