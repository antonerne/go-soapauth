package communications

type NewPasswordRequest struct {
	UserID      string `json:"id"`
	OldPassword string `json:"oldpassword"`
	NewPassword string `json:"newpassword"`
}

type AuthenticationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ForgotPasswordStartRequest struct {
	Email string `json:"email"`
}

type ForgotPasswordChangeRequest struct {
	UserID      string `json:"userid"`
	ResetToken  string `json:"resettoken"`
	NewPassword string `json:"newpassword"`
}
