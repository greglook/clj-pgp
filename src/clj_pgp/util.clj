(ns clj-pgp.util
  "Internal utility functions used by other namespaces.")


(defn arg-coll
  "Returns a collection from the arguments provided. If `args` is a
  non-collection value, a single-element collection containing `args` is
  returned."
  [args]
  (if (and args (not (coll? args)))
    (list args)
    (seq args)))


(defn arg-seq
  "Takes a sequence of args and returns a seq. If only one argument is given
  and it is sequential, it is retured directly. Otherwise the seq of args is
  returned. Returns nil for empty args."
  [args]
  (if (and (= 1 (count args))
           (sequential? (first args)))
    (seq (first args))
    (seq args)))


(defn arg-map
  "Takes a sequence of args and returns a map. If only one argument is given
  and it is a map, it is retured directly. Otherwise the seq of args is treated
  as keyword args and returned as a map."
  [args]
  (cond
    (nil? args) nil
    (map? args) args
    (= 1 (count args)) (recur (first args))
    :else (apply array-map args)))


(defn preserving-reduced
  "Returns a reducing function that double-wraps reduced values so that nested
  reductions properly halt an outer reduction.

  Adapted from `clojure.core`, which declares it as private."
  [rf]
  (fn wrapper
    ([acc]
     (rf acc))
    ([acc x]
     (let [ret (rf acc x)]
       (if (reduced? ret)
         (reduced ret)
         ret)))))
