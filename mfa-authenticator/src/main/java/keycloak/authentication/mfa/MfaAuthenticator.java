package keycloak.authentication.mfa;

import org.jboss.logging.Logger;
import jakarta.ws.rs.core.*;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.*;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;

import java.util.*;

import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

@Slf4j
public class MfaAuthenticator implements Authenticator {
	private static final Logger LOG = Logger.getLogger(MfaAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		UserModel user = context.getUser();
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

		// initialize the configuration values
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		int length = Integer.parseInt(config.getConfig().get(MfaConstants.CONFIG_PROPERTY_LENGTH));
		int ttl = Integer.parseInt(config.getConfig().get(MfaConstants.CONFIG_PROPERTY_TTL));
		int timeToResendOtp = Integer.parseInt(config.getConfig().get(MfaConstants.CONFIG_TIME_TO_RESEND_OTP));
		int maxInvalidOtpAttempt = Integer
				.parseInt(config.getConfig().get(MfaConstants.CONFIG_MAX_INVALID_OTP_ATTEMPT));
		boolean isMfaEnabled = Boolean.parseBoolean(config.getConfig().get(MfaConstants.CONFIG_IS_MFA_ENABLED));
		String skipOtpRole = config.getConfig().get(MfaConstants.CONFIG_SKIP_OTP_ROLE);
		int numOfDaysIgnoreOtp = Integer.parseInt(config.getConfig().get(MfaConstants.CONFIG_NUM_OF_DAYS_IGNORE_OTP));

		// if action="validate-password" verify the password without creating tokens.
		if (formData.containsKey("action") && Objects.equals(formData.getFirst("action"), "validate-password")) {
			Boolean isValid = user.credentialManager().isValid(UserCredentialModel.password(formData.getFirst("password")));

			Map response = Map.of("is_valid", isValid, "message", isValid ? "Valid password" : "Invalid password");
			
			context.challenge(Response.ok().entity(response).status(Response.Status.OK).build());
		}
		// check the MFA configuration is enabled or not
		else if (isMfaEnabled) {
			// if action="request-otp".
			if (formData.containsKey("action") && Objects.equals(formData.getFirst("action"), "request-otp")) {
				// check the previous OTP created time. if that time is within the configured
				// minimum two OTPs gap time send an error response. else generate new OTP.
				if (user.getAttributes().containsKey("otpCreatedTime") &&
						Long.valueOf(user.getFirstAttribute("otpCreatedTime"))
								+ Long.valueOf(timeToResendOtp) * 1000 > System.currentTimeMillis()) {

					MfaResponse errorRes = new MfaResponse(
							Response.Status.TOO_MANY_REQUESTS.getStatusCode(),
							"frequent_otp",
							"Minimum time gap two OTPs should be " + timeToResendOtp + " seconds");
					context.challenge(Response.ok(errorRes).status(Response.Status.TOO_MANY_REQUESTS).build());
				} else {
					String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

					user.setSingleAttribute("otp", code);
					user.setSingleAttribute("otpTryAttempt", "0");
					user.setSingleAttribute("otpCreatedTime", Long.toString(System.currentTimeMillis()));

					Map response = Map.of("message", "OTP created successfully");
					context.challenge(Response.ok().entity(response).status(Response.Status.CREATED).build());
				}
			}
			// if action="login" and user has the configured skip role. continue the flow
			// and generate the tokens without checking OTP.
			else if (formData.containsKey("action") && Objects.equals(formData.getFirst("action"), "login")
					&& this.userHasRole(context.getRealm(), user, skipOtpRole)) {
				context.success();
			}
			// if the otp ignore flag is enable, ignore the otp validation for configured
			// number of days.
			else if (formData.containsKey("action") && Objects.equals(formData.getFirst("action"), "login") &&
					user.getAttributes().containsKey("isOtpSkip")
					&& Objects.equals(user.getFirstAttribute("isOtpSkip"), "1") &&
					user.getAttributes().containsKey("otpSkipEndDate")
					&& Long.valueOf(user.getFirstAttribute("otpSkipEndDate")) > System.currentTimeMillis()) {

				context.success();
			}
			// if action="login" and OTP is set, do the OTP validation.
			else if (formData.containsKey("action") && Objects.equals(formData.getFirst("action"), "login")
					&& formData.containsKey("otp") && user.getAttributes().containsKey("otp")
					&& user.getAttributes().containsKey("otpCreatedTime")) {

				String otp = user.getFirstAttribute("otp");
				Long otpCreatedTime = Long.valueOf(user.getFirstAttribute("otpCreatedTime"));
				String userEnteredOtp = formData.getFirst("otp");

				// if OTP is invalid.
				if (userEnteredOtp == null || userEnteredOtp.isEmpty() || !Objects.equals(otp, userEnteredOtp)) {
					// increase the invalid attempt count by one.
					int otpTryAttempt = Integer.parseInt(user.getFirstAttribute("otpTryAttempt")) + 1;
					// invalid attempt count is lager than the configured max invalid attempt send
					// error "invalid_otp_reset". else send "invalid_otp".
					if (otpTryAttempt >= maxInvalidOtpAttempt) {
						String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

						user.setSingleAttribute("otp", code);
						user.setSingleAttribute("otpTryAttempt", "0");
						user.setSingleAttribute("otpCreatedTime", Long.toString(System.currentTimeMillis()));

						MfaResponse errorRes = new MfaResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
								"invalid_otp_reset", "Invalid OTP. Reset the OTP");
						context.challenge(Response.ok(errorRes).status(Response.Status.UNAUTHORIZED).build());
					} else {
						user.setSingleAttribute("otpTryAttempt", Integer.toString(otpTryAttempt));

						MfaResponse errorRes = new MfaResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
								"invalid_otp", "Invalid OTP");
						context.challenge(Response.ok(errorRes).status(Response.Status.UNAUTHORIZED).build());
					}
				}
				// check the OTP expiry with the configured expiration time.
				else if (otpCreatedTime + Long.valueOf(ttl) * 1000 < System.currentTimeMillis()) {
					MfaResponse errorRes = new MfaResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "expired_otp",
							"Expired OTP");
					context.challenge(Response.ok(errorRes).status(Response.Status.UNAUTHORIZED).build());
				}
				// if OTP is valid, continue to generate the token.
				else {
					user.removeAttribute("otp");
					user.removeAttribute("otpTryAttempt");
					user.removeAttribute("otpCreatedTime");

					user.setSingleAttribute("otpSkipEndDate", Long.toString(
							System.currentTimeMillis() + 1000 * 60 * 60 * 24 * Long.valueOf(numOfDaysIgnoreOtp)));

					context.success();
				}
			}
			// if action filed is not any of above, send an error.
			else {
				MfaResponse errorRes = new MfaResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant",
						"Invalid user credentials");
				context.challenge(Response.ok(errorRes).status(Response.Status.UNAUTHORIZED).build());
			}
		} else {
			context.success();
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

	}

	@Override
	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Authenticator.super.getRequiredActions(session);
	}

	@Override
	public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
		return Authenticator.super.areRequiredActionsEnabled(session, realm);
	}

	@Override
	public void close() {

	}

	private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

		if (roleName == null) {
			return false;
		}

		RoleModel role = getRoleFromString(realm, roleName);
		if (role != null) {
			return user.hasRole(role);
		}
		return false;
	}
}
