export function initializePDFToggle() {
    const toggle = document.getElementById('pdfToggle');
    if (!toggle) return;
  
    // Update visual state
    function updateToggleState() {
      const container = toggle.closest('.cyber-toggle');
      if (toggle.checked) {
        container.style.boxShadow = '0 0 10px var(--cyber-accent)';
      } else {
        container.style.boxShadow = 'none';
      }
    }
  
    // Initial state
    updateToggleState();
    
    // Add event listeners
    toggle.addEventListener('change', updateToggleState);
  }