package password

type passwordRequest struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Password string `json:"password"`
}
