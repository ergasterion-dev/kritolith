# Permissive CORS in gorilla/mux middleware package

gorilla/mux v1.8.1: `CORSMethodMiddleware` in the `github.com/gorilla/mux/middleware`
package reflects the request's `Origin` back in `Access-Control-Allow-Origin`, which
effectively allows any origin to read authenticated responses.

Impact: cross-origin data exposure for routers that install this middleware.
