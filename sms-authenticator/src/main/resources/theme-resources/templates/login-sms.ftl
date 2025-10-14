<form id="kc-sms-code-login-form"
	  class="${properties.kcFormClass!}"
	  action="${url.loginAction}" method="post">

	<input type="hidden" name="resend" id="resend" value="false"/>

	<div class="${properties.kcFormGroupClass!}">
		<div class="${properties.kcLabelWrapperClass!}">
			<label for="code" class="${properties.kcLabelClass!}">
                ${msg("smsAuthLabel")}
			</label>
		</div>
		<div class="${properties.kcInputWrapperClass!}">
			<input type="number" id="code" name="code" autocomplete="off" autofocus />
		</div>
	</div>

	<!-- Retry button with countdown -->
	<div style="margin-top: 1em; text-align: center;">
		<button id="retryButton" type="button" class="pf-v5-c-button pf-m-secondary" disabled>
			Resend Code (<span id="countdown">30</span>s)
		</button>
	</div>

	<div id="kc-form-buttons">
		<input name="login" class="pf-v5-c-button pf-m-primary" type="submit" value="${msg("doSubmit")}"/>
	</div>
</form>

<script>
	const retryButton = document.getElementById("retryButton");
	const countdownSpan = document.getElementById("countdown");
	const resendInput = document.getElementById("resend");
	const form = document.getElementById("kc-sms-code-login-form");

	function startCountdown() {
		let remaining = 30;
		retryButton.disabled = true;
		countdownSpan.textContent = remaining;

		const interval = setInterval(() => {
			remaining--;
			countdownSpan.textContent = remaining;
			if (remaining <= 0) {
				clearInterval(interval);
				retryButton.disabled = false;
				retryButton.textContent = "Resend Code";
			}
		}, 1000);
	}

	retryButton.addEventListener("click", () => {
		resendInput.value = "true";
		form.submit(); // normal Keycloak POST — no malformed Base64
	});

	startCountdown();
</script>
