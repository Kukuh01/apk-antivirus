// Simulated keylogger (safe for testing)
document.addEventListener('keypress', (e) => {
    console.log('Captured key: ' + e.key);
});
