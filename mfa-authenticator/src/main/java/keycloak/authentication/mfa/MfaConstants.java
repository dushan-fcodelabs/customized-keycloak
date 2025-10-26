package keycloak.authentication.mfa;

import lombok.experimental.UtilityClass;

@UtilityClass
public class MfaConstants {
	static String CONFIG_IS_MFA_ENABLED = "is_mfa_enabled"; // Whether MFA is enabled
	static String CONFIG_PROPERTY_LENGTH = "length"; // Length of the OTP
	static String CONFIG_PROPERTY_TTL = "ttl"; // Time to live for the OTP
	static String CONFIG_TIME_TO_RESEND_OTP= "time_to_resend_otp"; // Time before user can request a new OTP
	static String CONFIG_MAX_INVALID_OTP_ATTEMPT= "max_invalid_otp_attempt"; // Maximum invalid OTP attempts allowed
	static String CONFIG_SKIP_OTP_ROLE= "skip_otp_role"; // Role that allows skipping OTP
	static String CONFIG_NUM_OF_DAYS_IGNORE_OTP= "num_of_days_ignore_otp"; // Number of days to ignore OTP after successful authentication
}
