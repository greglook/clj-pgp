(ns mvxcvi.crypto.util
  (:require
    byte-streams
    [clojure.string :as str]))


;; BYTE PROCESSING

(def ^:dynamic *buffer-size*
  "Size of buffer to use in data functions."
  1024)


(defn apply-bytes
  "Calls the given function on chunks of the byte sequence read from the given
  data source. The function should accept a byte array and a number of bytes to
  use from it."
  [source f]
  (with-open [stream (byte-streams/to-input-stream source)]
    (let [buffer (byte-array *buffer-size*)]
      (loop [n (.read stream buffer)]
        (when (pos? n)
          (f buffer n)
          (recur (.read stream buffer)))))))


(defmacro do-bytes
  "Wraps the given statements in a function to pass to apply-bytes."
  [[[buff n] source] & body]
  `(let [f# (fn [~(vary-meta buff assoc :tag 'bytes)
                 ~(vary-meta n assoc :tag 'long)]
              ~@body)]
     (apply-bytes ~source f#)))



;; HEX CONVERSION

(defn- zero-pad
  "Pads a string"
  [width value]
  (let [string (str value)]
    (-> width
        (- (count string))
        (repeat "0")
        str/join
        (str string))))


(defmulti hex-str
  "Format the argument as a hexadecimal string."
  class)

(defmethod hex-str Long
  [^long value]
  (format "%016x" value))

(defmethod hex-str (class (byte-array 0))
  [^bytes value]
  (let [width (* 2 (count value))
        hex (-> (BigInteger. 1 value)
                (.toString 16)
                str/lower-case)]
    (zero-pad width hex)))
