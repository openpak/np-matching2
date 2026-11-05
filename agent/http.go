package agent

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Register adds the erasure route: DELETE /internal/accounts/{account}/data with the shared
// ACCOUNT_ERASE_KEY as bearer. The agent keeps login sessions only; rooms are erased in the matchmaking core.
func (a *Agent) Register(mux *http.ServeMux) {
	mux.HandleFunc("DELETE /internal/accounts/{account}/data", func(w http.ResponseWriter, r *http.Request) {
		key := os.Getenv("ACCOUNT_ERASE_KEY")
		b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || key == "" || subtle.ConstantTimeCompare([]byte(b), []byte(key)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		acct := r.PathValue("account")
		if !uuidRe.MatchString(acct) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n, err := a.Store.Erase(r.Context(), strings.ToLower(acct))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		a.log().Info("account erased", "sessions", n)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"deleted": n})
	})
}
