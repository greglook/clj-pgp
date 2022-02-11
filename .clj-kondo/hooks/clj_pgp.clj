(ns hooks.clj-pgp
  "Linter analysis hooks for clj-pgp macros."
  (:require
    [clj-kondo.hooks-api :as api]
    [clojure.string :as str]))


(defn deftags
  "Macro analysis for `clj-pgp.tags/deftags`."
  [form]
  (let [class-name (-> form :node :children second api/sexpr)
        tag-name (-> (name class-name)
                     (as-> s (subs s 0 (- (count s) 4)))
                     (str/replace #"([a-z])([A-Z])" "$1-$2")
                     (str/lower-case))
        define-map (api/list-node
                     [(api/token-node 'def)
                      (api/token-node (symbol (str tag-name "-tags")))
                      (api/map-node {})])
        define-code (api/list-node
                      [(api/token-node 'defn)
                       (api/token-node (symbol (str tag-name "-code")))
                       (api/vector-node
                         [(api/token-node '_)])])
        define-tag (api/list-node
                     [(api/token-node 'defn)
                      (api/token-node (symbol (str tag-name "-tag")))
                      (api/vector-node
                        [(api/token-node '_)])])
        expanded (api/list-node
                   [(api/token-node 'do)
                    (api/token-node class-name)
                    define-map
                    define-code
                    define-tag])]
    {:node expanded}))


(defn defalgorithms
  "Macro analysis for `clj-pgp.core/defalgorithms`."
  [form]
  (let [algo-type (-> form :node :children second api/sexpr)
        expanded (api/list-node
                   [(api/token-node 'def)
                    (api/token-node (symbol (str algo-type "-algorithms")))
                    (api/token-node nil)])]
    {:node expanded}))
