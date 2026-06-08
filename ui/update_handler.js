async function triggerUpdate() {
    const btn = document.getElementById('update-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Updating...';
    btn.classList.add('opacity-50', 'cursor-not-allowed');

    try {
        const response = await fetch('/setup/update', { method: 'POST' });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Update failed');
        }
        const data = await response.json();
        alert(data.message);

        // The server is restarting, so the page will naturally lose connection.
        // We suggest the user refresh in a few seconds.
        setTimeout(() => {
            window.location.reload();
        }, 5000);

    } catch (err) {
        alert('Critical Error: ' + err.message);
        btn.disabled = false;
        btn.textContent = originalText;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}
