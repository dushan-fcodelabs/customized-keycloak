package keycloak.authentication.mfa;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.List;

public class MfaAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "custom-mfa";

	private static final Authenticator SINGLETON = new MfaAuthenticator();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "Multi-Factor-Authentication";
	}

	@Override
	public String getHelpText() {
		return """
				This custom authenticator provides multi-factor authentication (MFA) capabilities by generating
				and validating one-time passwords (OTPs). It allows configuration of OTP length, time-to-live (TTL),
				resend intervals, maximum invalid attempts, and role-based OTP skipping. Users can request OTPs and
				validate their passwords through defined actions, enhancing security during the authentication process.

				Configuration Options:
				- is_mfa_enabled: Enable or disable MFA.
				- length: Length of the generated OTP.
				- ttl: Time-to-live for the OTP in seconds.
				- time_to_resend_otp: Minimum time gap between two OTP requests in seconds.
				- max_invalid_otp_attempt: Maximum number of invalid OTP attempts allowed.
				- skip_otp_role: Role that allows users to skip OTP verification.
				- num_of_days_ignore_otp: Number of days to ignore OTP validation after one successful authentication.
				""";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		ProviderConfigProperty isMfaEnabled = new ProviderConfigProperty();
		isMfaEnabled.setRequired(true);
		isMfaEnabled.setName(MfaConstants.CONFIG_IS_MFA_ENABLED);
		isMfaEnabled.setLabel("MFA enable status");
		isMfaEnabled.setHelpText("Enable the MFA authentication.");
		isMfaEnabled.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		isMfaEnabled.setDefaultValue(false);

		ProviderConfigProperty length = new ProviderConfigProperty();
		length.setRequired(true);
		length.setName(MfaConstants.CONFIG_PROPERTY_LENGTH);
		length.setLabel("Code length");
		length.setHelpText("The number of digits of the generated code.");
		length.setType(ProviderConfigProperty.STRING_TYPE);
		length.setDefaultValue("6");

		ProviderConfigProperty ttl = new ProviderConfigProperty();
		ttl.setRequired(true);
		ttl.setName(MfaConstants.CONFIG_PROPERTY_TTL);
		ttl.setLabel("Time-to-live");
		ttl.setHelpText("The time to live in seconds for the code to be valid.");
		ttl.setType(ProviderConfigProperty.STRING_TYPE);
		ttl.setDefaultValue("600");

		ProviderConfigProperty timeToResendOtp = new ProviderConfigProperty();
		timeToResendOtp.setRequired(true);
		timeToResendOtp.setName(MfaConstants.CONFIG_TIME_TO_RESEND_OTP);
		timeToResendOtp.setLabel("Time to resend OTP");
		timeToResendOtp.setHelpText("The minimum time gap between two OTPs in seconds.");
		timeToResendOtp.setType(ProviderConfigProperty.STRING_TYPE);
		timeToResendOtp.setDefaultValue("60");

		ProviderConfigProperty maxInvalidOtpAttempt = new ProviderConfigProperty();
		maxInvalidOtpAttempt.setRequired(true);
		maxInvalidOtpAttempt.setName(MfaConstants.CONFIG_MAX_INVALID_OTP_ATTEMPT);
		maxInvalidOtpAttempt.setLabel("Max invalid OTP attempt");
		maxInvalidOtpAttempt
				.setHelpText("Maximum number of invalid OPT attempt. Reset the OTP after this number of OTP attempt.");
		maxInvalidOtpAttempt.setType(ProviderConfigProperty.STRING_TYPE);
		maxInvalidOtpAttempt.setDefaultValue("3");

		ProviderConfigProperty skipOtpRole = new ProviderConfigProperty();
		skipOtpRole.setType(ProviderConfigProperty.ROLE_TYPE);
		skipOtpRole.setName(MfaConstants.CONFIG_SKIP_OTP_ROLE);
		skipOtpRole.setLabel("Skip OTP for role");
		skipOtpRole.setHelpText("OTP is always skipped if user has the given role.");

		ProviderConfigProperty numOfDaysIgnoreOtp = new ProviderConfigProperty();
		numOfDaysIgnoreOtp.setRequired(true);
		numOfDaysIgnoreOtp.setDefaultValue("30");
		numOfDaysIgnoreOtp.setType(ProviderConfigProperty.STRING_TYPE);
		numOfDaysIgnoreOtp.setName(MfaConstants.CONFIG_NUM_OF_DAYS_IGNORE_OTP);
		numOfDaysIgnoreOtp.setLabel("Skip OTP validation for days");
		numOfDaysIgnoreOtp.setHelpText("Skip the OTP validation number of days given here.");

		return List.of(
				isMfaEnabled,
				length,
				ttl,
				timeToResendOtp,
				maxInvalidOtpAttempt,
				skipOtpRole,
				numOfDaysIgnoreOtp);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}
