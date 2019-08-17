(ns clj-pgp.error)


(defn default-error-handler
  "Default error handling function which throws an exception with the provided
  data."
  [error-type message data cause]
  (throw (ex-info message (assoc data :pgp/error error-type) cause)))


(def ^:dynamic *handler*
  "Dynamic error handler"
  default-error-handler)


(derive :clj-pgp.core/read-object-error ::decrypt-error)
