package auth

import (
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"errors"
	"gitea.com/go-chi/session"
	"github.com/goccy/go-json"
	"io"
	"net/http"
	"net/url"
)

// Ensure the struct implements the interface.
var (
	_ Method = &BKSession{}
)

type BKSession struct{}

// Name represents the name of auth method
func (s *BKSession) Name() string {
	return "bk_session"
}

// Verify checks if there is a user uid stored in the session and returns the user
// object for that uid.
// Returns nil if there is no user uid stored in the session.
func (s *BKSession) Verify(req *http.Request, w http.ResponseWriter, store DataStore, sess SessionStore) (*user_model.User, error) {
	bkCookieName := "bk_token"
	bkToken := session.GetCookie(req, bkCookieName)
	if bkToken == "" {
		return nil, nil
	}

	username, err := getUsername(bkToken)
	if err != nil {
		log.Error("Get username from blueking failed: %v", err)
		return nil, err
	}

	// Get user object
	user, err := user_model.GetUserByName(req.Context(), username)
	if err != nil {
		if !user_model.IsErrUserNotExist(err) {
			log.Error("GetUserByID: %v", err)
			// Return the err as-is to keep current signed-in session, in case the err is something like context.Canceled. Otherwise non-existing user (nil, nil) will make the caller clear the signed-in session.
			return nil, err
		}
		return nil, nil
	}

	log.Trace("Session Authorization: Logged in user %-v", user)
	return user, nil
}

type BKResponse struct {
	Result  bool        `json:"result"`
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"` // 定义为 interface{}，因为 data 可以是任意类型，这里是空对象({})
}

// getUsername get username from blueking
func getUsername(BKToken string) (string, error) {
	isLoginUrl, _ := url.JoinPath(setting.BKAuthClient.BKPaasLoginUrl, "accounts", "is_login")
	params := url.Values{}
	params.Add("bk_token", BKToken)
	queryString := params.Encode()
	resp, err := http.Get(isLoginUrl + "/?" + queryString)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	var result BKResponse
	if err = json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.Result {
		return "", errors.New(result.Message)
	}
	username := result.Data.(map[string]interface{})["username"].(string)
	return username, nil
}
