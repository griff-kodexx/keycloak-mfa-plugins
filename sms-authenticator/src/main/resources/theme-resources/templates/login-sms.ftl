<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section == "header">
        ${msg("smsAuthTitle", realm.displayName)}
    <#elseif section == "form">
		<form onsubmit="login.disabled = true; return true;"
			  id="kc-sms-code-login-form"
			  class="${properties.kcFormClass!}"
			  action="${url.loginAction}"
			  method="post">

			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="code" class="${properties.kcLabelClass!}">
                        ${msg("smsAuthLabel")}
					</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="number" min="0" inputmode="numeric" pattern="[0-9]*"
						   id="code" name="code"
						   class="${properties.kcInputClass!}"
						   autocomplete="off" autofocus />
				</div>
			</div>

			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
					<div class="${properties.kcFormOptionsWrapperClass!}">
						<span><a href="/">${msg("backToApplication")?no_esc}</a></span>
					</div>
				</div>

				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input name="login"
						   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
						   type="submit" value="${msg("doSubmit")}" />
				</div>

				<!-- Centered Resend Section -->
				<div id="kc-resend-section" class="resend-container">
					<p class="resend-text">Didn’t receive the code?</p>
					<button id="resend-btn" type="button" class="resend-btn" disabled>
						Resend – <span id="resend-timer">01:00</span>
					</button>
				</div>
			</div>
		</form>

		<style>
			/* --- Centered and visually balanced resend section --- */
			.resend-container {
				display: flex;
				flex-direction: column;
				align-items: center;
				justify-content: center;
				text-align: center;
				margin-top: 1.8rem;
				width: 100%;
			}

			.resend-text {
				margin: 0 0 0.4rem 0;
				font-size: 0.95rem;
				color: #555;
				text-align: center;
			}

			.resend-btn {
				background: none;
				border: none;
				font-size: 0.95rem;
				cursor: not-allowed;
				color: #999;
				transition: color 0.3s ease, transform 0.2s ease;
				text-align: center;
			}

			.resend-btn.active {
				color: #652171; /* your brand color */
				cursor: pointer;
				font-weight: 600;
			}

			.resend-btn.active:hover {
				transform: scale(1.03);
			}

			.resend-btn:focus {
				outline: none;
			}
		</style>
		<script>
			(function() {

				const resendBtn = document.getElementById('resend-btn');
				const resendTimer = document.getElementById('resend-timer');
				const RESEND_URL = window.location.href;
				const COUNTDOWN_TIME = 10; // seconds
				const STORAGE_KEY = 'resendCooldownUntil';

				function formatTime(sec) {
					const m = String(Math.floor(sec / 60)).padStart(2, '0');
					const s = String(sec % 60).padStart(2, '0');
					return m + ':' + s;
				}

				function startCountdown(secondsLeft) {
					resendBtn.disabled = true;
					resendBtn.classList.remove('active');
					resendBtn.innerHTML = "Resend – <span id='resend-timer'>" + formatTime(secondsLeft) + "</span>";

					const timerInterval = setInterval(() => {
						secondsLeft--;
						const timerSpan = document.getElementById('resend-timer');
						if (timerSpan) timerSpan.textContent = formatTime(secondsLeft);

						if (secondsLeft <= 0) {
							clearInterval(timerInterval);
							localStorage.removeItem(STORAGE_KEY);
							resendBtn.disabled = false;
							resendBtn.classList.add('active');
							resendBtn.textContent = 'Resend';
						}
					}, 1000);
				}

				// --- Resume or start timer on page load ---
				const now = Date.now();
				const storedExpire = parseInt(localStorage.getItem(STORAGE_KEY), 10);

				if (storedExpire && now < storedExpire) {
					// Continue from stored time
					const secondsLeft = Math.max(0, Math.ceil((storedExpire - now) / 1000));
					startCountdown(secondsLeft);
				} else {
					// Always start fresh countdown on first load
					const cooldownUntil = now + COUNTDOWN_TIME * 1000;
					localStorage.setItem(STORAGE_KEY, cooldownUntil);
					startCountdown(COUNTDOWN_TIME);
				}

				resendBtn.addEventListener('click', () => {
					if (resendBtn.disabled) return;

					resendBtn.disabled = true;
					resendBtn.classList.remove('active');
					resendBtn.textContent = 'Sending...';

					fetch(RESEND_URL, { method: 'POST' })
						.then(resp => {
							if (!resp.ok) throw new Error('Failed to resend');
							resendBtn.textContent = 'Code Sent!';
							const cooldownUntil = Date.now() + COUNTDOWN_TIME * 1000;
							localStorage.setItem(STORAGE_KEY, cooldownUntil);
							setTimeout(() => startCountdown(COUNTDOWN_TIME), 1000);
						})
						.catch(() => {
							resendBtn.textContent = 'Error. Try Again';
							setTimeout(() => {
								resendBtn.textContent = 'Resend';
								resendBtn.disabled = false;
								resendBtn.classList.add('active');
							}, 2000);
						});
				});
			})();
		</script>



    <#elseif section == "info">
        ${msg("smsAuthInstruction")}
    </#if>
</@layout.registrationLayout>
