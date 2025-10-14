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

				<!-- Resend Section -->
				<div id="kc-resend-section" class="resend-container">
					<p class="resend-text">Didn’t receive the code?</p>
					<button id="resend-btn" type="button" class="resend-btn" disabled>
						Resend – <span id="resend-timer">01:00</span>
					</button>
				</div>
			</div>
		</form>

		<style>
			/* --- Centered resend section --- */
			.resend-container {
				text-align: center;
				margin-top: 1.5rem;
			}

			.resend-text {
				margin: 0 0 0.4rem 0;
				font-size: 0.95rem;
				color: #555;
			}

			.resend-btn {
				background: none;
				border: none;
				font-size: 0.95rem;
				cursor: not-allowed;
				color: #999;
				transition: color 0.3s ease;
			}

			.resend-btn.active {
				color: #652171; /* your brand color */
				cursor: pointer;
				font-weight: 600;
			}

			.resend-btn:focus {
				outline: none;
			}
		</style>
		<script>
			(function() {
				const resendBtn = document.getElementById('resend-btn');
				const resendTimer = document.getElementById('resend-timer');
				const RESEND_URL = window.location.href

				let countdown = 60;

				// Format seconds as mm:ss
				function formatTime(sec) {
					const m = String(Math.floor(sec / 60)).padStart(2, '0');
					const s = String(sec % 60).padStart(2, '0');
					return m + ':' + s;
				}

				resendTimer.textContent = formatTime(countdown);

				const timer = setInterval(() => {
					countdown--;
					resendTimer.textContent = formatTime(countdown);
					if (countdown <= 0) {
						clearInterval(timer);
						resendBtn.disabled = false;
						resendBtn.classList.add('active');
						resendBtn.textContent = 'Resend';
					}
				}, 1000);

				resendBtn.addEventListener('click', () => {
					if (resendBtn.disabled) return;
					resendBtn.disabled = true;
					resendBtn.classList.remove('active');
					resendBtn.textContent = 'Sending...';

					fetch(RESEND_URL, { method: 'GET' })
						.then(resp => {
							if (!resp.ok) throw new Error('Failed to resend');
							resendBtn.textContent = 'Code Sent!';
							setTimeout(() => location.reload(), 1500);
						})
						.catch(() => {
							resendBtn.textContent = 'Error. Try Again';
							setTimeout(() => location.reload(), 2000);
						});
				});
			})();
		</script>

    <#elseif section == "info">
        ${msg("smsAuthInstruction")}
    </#if>
</@layout.registrationLayout>
