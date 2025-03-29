// fileInteractions.js
// Contains file drag & drop functionality. This file will be used to handle file uploads and drag & drop interactions.

export function setupFileDragAndDrop() {
    const fileInput = document.getElementById('fileInput');
    const uploadZone = document.querySelector('.upload-zone');
    
    if (!fileInput || !uploadZone) {
      console.warn("File input or upload zone element not found.");
      return;
    }
  
    uploadZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadZone.classList.add('dragover');
    });
  
    uploadZone.addEventListener('dragleave', () => {
      uploadZone.classList.remove('dragover');
    });
  
    uploadZone.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadZone.classList.remove('dragover');
      fileInput.files = e.dataTransfer.files;
    });
  }
  