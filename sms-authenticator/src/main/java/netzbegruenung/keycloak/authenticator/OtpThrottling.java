/*
 * Copyright 2024 Netzbegruenung e.V. and contributors
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
 */

package netzbegruenung.keycloak.authenticator;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Per-user OTP abuse controls shared by the login authenticator
 * ({@link SmsAuthenticator}) and the registration required action
 * ({@link PhoneValidationRequiredAction}).
 *
 * <p>State is held in Keycloak's {@link SingleUseObjectProvider}, keyed by
 * realm + user id. Unlike the brute-force login-failure store it is NOT cleared
 * when the user later enters a correct username/password, so the counters
 * survive a brand-new authentication session. Entries auto-expire via TTL.</p>
 */
public final class OtpThrottling {

	private OtpThrottling() {
	}

	private static String failKey(RealmModel realm, UserModel user) {
		return "sms-otp-fail:" + realm.getId() + ":" + user.getId();
	}

	private static String lockKey(RealmModel realm, UserModel user) {
		return "sms-otp-lock:" + realm.getId() + ":" + user.getId();
	}

	private static String sendKey(RealmModel realm, UserModel user) {
		return "sms-otp-send:" + realm.getId() + ":" + user.getId();
	}

	/** Reads a positive int from a config map, falling back to {@code fallback}. */
	public static int intConfig(Map<String, String> config, String key, int fallback) {
		try {
			int value = Integer.parseInt(config != null ? config.get(key) : null);
			return value > 0 ? value : fallback;
		} catch (NumberFormatException e) {
			return fallback;
		}
	}

	/** True when this user is currently inside an OTP lockout window. */
	public static boolean isLocked(KeycloakSession session, RealmModel realm, UserModel user) {
		if (user == null) {
			return false;
		}
		return session.singleUseObjects().get(lockKey(realm, user)) != null;
	}

	/**
	 * Records a failed OTP verification. Returns {@code true} when this failure
	 * reached the threshold and the user is now locked out.
	 */
	public static boolean recordFailure(KeycloakSession session, RealmModel realm, UserModel user,
										int maxAttempts, int lockSeconds) {
		SingleUseObjectProvider store = session.singleUseObjects();
		String fk = failKey(realm, user);
		int next = readCount(store.get(fk), "count") + 1;
		store.remove(fk);

		if (next >= maxAttempts) {
			String lk = lockKey(realm, user);
			store.remove(lk);
			store.put(lk, lockSeconds, Map.of("ts", Long.toString(System.currentTimeMillis())));
			return true;
		}
		store.put(fk, lockSeconds, Map.of("count", Integer.toString(next)));
		return false;
	}

	/**
	 * Counts an OTP send for this user. Returns {@code true} when the user has
	 * exceeded {@code maxSends} within the rolling window and the send should be
	 * refused. Survives new authentication sessions.
	 */
	public static boolean registerSendAndIsExceeded(KeycloakSession session, RealmModel realm, UserModel user,
													int maxSends, int windowSeconds) {
		SingleUseObjectProvider store = session.singleUseObjects();
		String sk = sendKey(realm, user);
		int next = readCount(store.get(sk), "count") + 1;
		store.remove(sk);
		store.put(sk, windowSeconds, Map.of("count", Integer.toString(next)));
		return next > maxSends;
	}

	/** Clears all OTP counters/lock for this user (call on successful OTP). */
	public static void clear(KeycloakSession session, RealmModel realm, UserModel user) {
		if (user == null) {
			return;
		}
		SingleUseObjectProvider store = session.singleUseObjects();
		store.remove(failKey(realm, user));
		store.remove(lockKey(realm, user));
		store.remove(sendKey(realm, user));
	}

	private static int readCount(Map<String, String> data, String field) {
		if (data == null) {
			return 0;
		}
		try {
			return Integer.parseInt(data.get(field));
		} catch (NumberFormatException e) {
			return 0;
		}
	}
}
