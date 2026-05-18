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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.events.Errors;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	static final String TPL_CODE = "login-sms.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		if (isTemporarilyLockedOut(context)) {
			return;
		}

		Optional<CredentialModel> model = context.getUser().credentialManager().getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		String mobileNumber;
		try {
			mobileNumber = JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e1) {
			logger.warn(e1.getMessage(), e1);
			return;
		}

		int length = Integer.parseInt(config.getConfig().get("length"));
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		logger.infof("Validating OTP for phone number: %s of user: %s", mobileNumber, user.getUsername());

		var maxAttemptsReached = SmsAuthenticator.checkAndSetResendCodeMaxAttempts(authSession);
		if (maxAttemptsReached) {
			logger.infof("Max OTP reached for setting up 2FA for phone number: %s of user: %s", mobileNumber, user.getUsername());
			handleMaxAttemptsReached(context);
			return;
		}

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, user.getEmail(), smsText);

			context.challenge(context.form().setAttribute("realm", realm).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		// If brute force protection already locked the user mid-session, stop here.
		if (isTemporarilyLockedOut(context)) {
			return;
		}

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
		// Constant-time comparison to avoid leaking the code via timing.
		boolean isValid = enteredCode != null && MessageDigest.isEqual(
			enteredCode.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8));

		if (isValid && Long.parseLong(ttl) >= System.currentTimeMillis()) {
			// Valid and not expired: consume the code so it can never be replayed.
			invalidateCode(authSession);
			context.success();
			return;
		}

		if (isValid) {
			// Correct but expired: still consume it.
			invalidateCode(authSession);
			context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
				context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}

		// Wrong code: count the failed attempt per-session and feed Keycloak's
		// per-user brute force protector (which persists across login sessions,
		// so re-authenticating with the password does not reset the limit).
		int maxAttempts = getMaxVerifyAttempts(context);
		int attempts = Integer.parseInt(
			authSession.getAuthNote(AUTH_NOTE_VERIFY_ATTEMPTS) != null
				? authSession.getAuthNote(AUTH_NOTE_VERIFY_ATTEMPTS) : "0") + 1;
		authSession.setAuthNote(AUTH_NOTE_VERIFY_ATTEMPTS, Integer.toString(attempts));

		context.getEvent().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
		RealmModel realm = context.getRealm();
		if (realm.isBruteForceProtected()) {
			context.getProtector().failedLogin(realm, context.getUser(),
				context.getConnection(), context.getUriInfo());
		}

		if (attempts >= maxAttempts) {
			// Too many wrong guesses: invalidate the code and terminate the flow.
			// The user must restart authentication, which is itself resend-capped.
			invalidateCode(authSession);
			logger.warnf("Max OTP verification attempts (%d) reached for user: %s; failing authentication",
				maxAttempts, context.getUser().getUsername());
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
				context.form().setError("smsAuthMaxAttemptsReached").createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}

		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
			context.form().setAttribute("realm", context.getRealm())
				.setError("smsAuthCodeInvalid").createForm(TPL_CODE));
	}

	private static final String AUTH_NOTE_VERIFY_ATTEMPTS = "verifyAttempts";

	private static int getMaxVerifyAttempts(AuthenticationFlowContext context) {
		String configured = context.getAuthenticatorConfig() != null
			? context.getAuthenticatorConfig().getConfig().get("maxVerifyAttempts") : null;
		try {
			int value = Integer.parseInt(configured);
			return value > 0 ? value : 3;
		} catch (NumberFormatException e) {
			return 3;
		}
	}

	private static void invalidateCode(AuthenticationSessionModel authSession) {
		authSession.removeAuthNote("code");
		authSession.removeAuthNote("ttl");
		authSession.removeAuthNote(AUTH_NOTE_VERIFY_ATTEMPTS);
	}

	private boolean isTemporarilyLockedOut(AuthenticationFlowContext context) {
		RealmModel realm = context.getRealm();
		UserModel user = context.getUser();
		if (user != null && realm.isBruteForceProtected()
			&& context.getProtector().isTemporarilyDisabled(context.getSession(), realm, user)) {
			logger.warnf("User %s is temporarily locked out by brute force protection; blocking OTP step",
				user.getUsername());
			context.failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
			return true;
		}
		return false;
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
	}

	@Override
	public void close() {
	}

	@Override
	public SmsAuthCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (SmsAuthCredentialProvider)session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
	}

	public static boolean checkAndSetResendCodeMaxAttempts(AuthenticationSessionModel authSession) {
		int max = 5;
        int currentAttempts = Integer.parseInt((authSession.getAuthNote("sessionVarResendCodeAttempts") != null ? authSession.getAuthNote("sessionVarResendCodeAttempts") : "0"));
		if (currentAttempts >= max) {
			return true;
		}
		authSession.setAuthNote("sessionVarResendCodeAttempts", Integer.toString(currentAttempts + 1));
		return false;
	}

	public void handleMaxAttemptsReached(AuthenticationFlowContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("resendCodeMaxAttemptsReached")
			.createForm("login-sms.ftl");
		context.challenge(challenge);
	}
}
