package keycloak.authentication.mfa;

public class MfaResponse {
	private int status;
	private String error;
	private String error_description;

	public MfaResponse(int status, String error, String error_description) {
		this.status = status;
		this.error = error;
		this.error_description = error_description;
	}

	public int getStatus() {
		return this.status;
	}

	public String getError() {
		return this.error;
	}

	public String getError_description() {
		return this.error_description;
	}
}
