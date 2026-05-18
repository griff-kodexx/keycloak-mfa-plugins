/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import jakarta.ws.rs.core.Response;

public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.getUser().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
			Map<String, String> cfgMap = (config != null && config.getConfig() != null) ? config.getConfig() : Map.of();

			if (OtpThrottling.isLocked(context.getSession(), realm, user)) {
				logger.warnf("User %s is locked out of OTP; blocking phone validation", user.getUsername());
				context.challenge(context.form().setError("smsAuthAccountLocked").createErrorPage(Response.Status.UNAUTHORIZED));
				return;
			}

			int maxSends = OtpThrottling.intConfig(cfgMap, "maxOtpSends", 5);
			int sendWindow = OtpThrottling.intConfig(cfgMap, "otpLockoutSeconds", 900);
			if (OtpThrottling.registerSendAndIsExceeded(context.getSession(), realm, user, maxSends, sendWindow)) {
				logger.warnf("User %s exceeded OTP send budget (%d); refusing to send", user.getUsername(), maxSends);
				context.challenge(context.form().setError("resendCodeMaxAttemptsReached").createErrorPage(Response.Status.TOO_MANY_REQUESTS));
				return;
			}

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			var maxAttemptsReached = SmsAuthenticator.checkAndSetResendCodeMaxAttempts(authSession);
			if (maxAttemptsReached) {
				logger.infof("Max OTP reached for setting up 2FA for phone number: %s of user: %s", mobileNumber, user.getUsername());
				handleMaxAttemptsReached(context);
				return;
			}


			int length = Integer.parseInt(config.getConfig().get("length"));
			int ttl = Integer.parseInt(config.getConfig().get("ttl"));

			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote("code", code);
			authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			Locale locale = context.getSession().getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, user.getEmail(), smsText);

			Response challenge = context.form()
				.setAttribute("realm", realm)
				.createForm(SmsAuthenticator.TPL_CODE);
			context.challenge(challenge);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		if (OtpThrottling.isLocked(context.getSession(), realm, user)) {
			logger.warnf("User %s is locked out of OTP; blocking phone validation", user.getUsername());
			context.challenge(context.form().setError("smsAuthAccountLocked").createErrorPage(Response.Status.UNAUTHORIZED));
			return;
		}

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null || enteredCode.isBlank()) {
			// Missing state, or no code submitted (e.g. the resend button POSTs
			// with no "code"): re-prompt WITHOUT counting it as a failure.
			handleInvalidSmsCode(context);
			return;
		}

		// Constant-time comparison to avoid leaking the code via timing.
		boolean matches = MessageDigest.isEqual(
			enteredCode.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8));

		if (matches && Long.parseLong(ttl) > System.currentTimeMillis()) {
			// valid: register the credential and clear OTP counters for the user
			SmsAuthCredentialProvider smnp = (SmsAuthCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "mobile-number");
			if (!smnp.isConfiguredFor(realm, user, SmsAuthCredentialModel.TYPE)) {
				smnp.createCredential(realm, user, SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber));
			} else {
				smnp.updateCredential(
					realm,
					user,
					new UserCredentialModel("random_id", "mobile-number", mobileNumber)
				);
			}
			OtpThrottling.clear(context.getSession(), realm, user);
			user.removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			handlePhoneToAttribute(context, mobileNumber);
			context.success();
			return;
		}

		if (matches) {
			// Correct but expired: do not penalise, just re-prompt.
			handleInvalidSmsCode(context);
			return;
		}

		// Wrong code: record the failure in the shared, cross-session store.
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		Map<String, String> cfgMap = (config != null && config.getConfig() != null) ? config.getConfig() : Map.of();
		int maxAttempts = OtpThrottling.intConfig(cfgMap, "maxVerifyAttempts", 5);
		int lockSeconds = OtpThrottling.intConfig(cfgMap, "otpLockoutSeconds", 900);

		context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
		boolean nowLocked = OtpThrottling.recordFailure(context.getSession(), realm, user, maxAttempts, lockSeconds);
		if (nowLocked) {
			logger.warnf("Max OTP verification attempts (%d) reached for user: %s; locking OTP for %d s",
				maxAttempts, user.getUsername(), lockSeconds);
			context.challenge(context.form().setError("smsAuthMaxAttemptsReached").createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}

		handleInvalidSmsCode(context);
	}

	private void handlePhoneToAttribute(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.warn("No config alias sms-2fa found, skip phone number to attribute check");
		} else {
			if (Boolean.parseBoolean(config.getConfig().get("storeInAttribute"))) {
				context.getUser().setSingleAttribute("mobile_number", mobileNumber);
			}
		}
	}

	private void handleInvalidSmsCode(RequiredActionContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("smsAuthCodeInvalid")
			.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}

	public void handleMaxAttemptsReached(RequiredActionContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("resendCodeMaxAttemptsReached")
			.createForm("login-sms.ftl");
		context.challenge(challenge);
	}
}
