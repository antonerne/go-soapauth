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

type NewUserRequest struct {
	Email      string `json:"email"`
	FirstName  string `json:"first"`
	MiddleName string `json:"middle,omitempty"`
	LastName   string `json:"last"`
	NameSuffix string `json:"suffix,omitempty"`
	Password   string `json:"password"`
}

type UpdateUserRequest struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Field string `json:"field"`
	Value string `json:"value"`
}
