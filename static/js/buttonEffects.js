// buttonEffects.js

export function setupButtonEffects() {
    document.querySelectorAll('.cyber-button').forEach(button => {
      button.addEventListener('mousedown', () => {
        button.style.transform = 'scale(0.95)';
      });
      
      button.addEventListener('mouseup', () => {
        button.style.transform = 'scale(1)';
      });
    });
  
    const analyzeButton = document.querySelector('button[type="submit"]');
    if (analyzeButton) {
      analyzeButton.addEventListener('click', function(e) {
        if (this.form.checkValidity()) {
          this.classList.add('processing');
          this.innerHTML = '<div class="button-lights"><span class="light red"></span><span class="light yellow"></span><span class="light green"></span></div>';
          setTimeout(() => {
            this.style.color = 'transparent';
          }, 300);
          this.classList.add('disabled');
        }
      });
  
      document.querySelector('form').addEventListener('invalid', () => {
        analyzeButton.classList.remove('processing', 'disabled');
        analyzeButton.style.color = '';
      }, true);
    }
  }
  