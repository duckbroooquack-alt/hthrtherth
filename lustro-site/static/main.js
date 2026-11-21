// 1. Интерактивный Minecraft-инвентарь модулей с тултипом
const invSlots = document.querySelectorAll('.inv-slot');
const tipTitle = document.getElementById('mc-tip-title');
const tipLore = document.getElementById('mc-tip-lore');
const activeCounter = document.getElementById('active-modules-count');

function updateActiveCount() {
    if (!activeCounter) return;
    const active = document.querySelectorAll('.inv-slot.active').length;
    activeCounter.textContent = `${active} / ${invSlots.length} ВКЛ`;
}

invSlots.forEach(slot => {
    slot.addEventListener('mouseenter', () => {
        if (tipTitle) tipTitle.textContent = slot.dataset.title;
        if (tipLore) tipLore.textContent = slot.dataset.lore;
    });

    slot.addEventListener('click', () => {
        slot.classList.toggle('active');
        const stateEl = slot.querySelector('.slot-state');
        if (stateEl) {
            stateEl.textContent = slot.classList.contains('active') ? '[ВКЛ]' : '[ВЫКЛ]';
        }
        if (tipTitle) tipTitle.textContent = slot.dataset.title;
        if (tipLore) tipLore.textContent = slot.dataset.lore;
        updateActiveCount();
    });
});
updateActiveCount();

// 2. Обновление SVG-капчи по клику
const captchaImg = document.getElementById('captcha-img');
const refreshBtn = document.getElementById('captcha-refresh');

function reloadCaptcha() {
    if (captchaImg) {
        captchaImg.src = '/captcha.svg?t=' + Date.now();
    }
}
if (captchaImg) captchaImg.addEventListener('click', reloadCaptcha);
if (refreshBtn) refreshBtn.addEventListener('click', reloadCaptcha);

// 3. Живая проверка существования Email при регистрации
const emailInput = document.getElementById('reg-email');
const emailStatus = document.getElementById('email-status');
let emailTimer = null;

if (emailInput && emailStatus) {
    emailInput.addEventListener('input', () => {
        clearTimeout(emailTimer);
        const val = emailInput.value.trim();
        if (!val || !val.includes('@')) {
            emailStatus.textContent = '';
            emailStatus.className = 'email-status';
            return;
        }
        emailStatus.textContent = 'Проверяем почтовый домен...';
        emailStatus.className = 'email-status email-wait';

        emailTimer = setTimeout(async () => {
            try {
                const res = await fetch('/api/check-email?email=' + encodeURIComponent(val));
                const data = await res.json();
                emailStatus.textContent = data.message;
                emailStatus.className = 'email-status ' + (data.ok ? 'email-ok' : 'email-bad');
            } catch {
                emailStatus.textContent = '';
            }
        }, 550);
    });
}

// 4. FAQ Аккордеон
document.querySelectorAll('.faq-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        btn.parentElement.classList.toggle('open');
    });
});