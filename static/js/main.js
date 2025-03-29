// main.js

// Import the functions from the other modules
import { loadVisualizations } from './visualizations.js';
import { setupFileDragAndDrop } from './fileInteractions.js';
import { setupButtonEffects } from './buttonEffects.js';
import { initializePDFToggle } from './interaction.js';


document.addEventListener('DOMContentLoaded', () => {
  // Read the initial report filename from a DOM element's data attribute (or use default)
  const initialReport = document.getElementById('reportFilename')?.dataset.report || 'latest_analysis.json';
  
  // Load visualizations using the chosen report file
  loadVisualizations(initialReport);
  
  // Initialize file drag and drop functionality
  setupFileDragAndDrop();
  
  // Initialize button effects
  setupButtonEffects();
  
  // Initialize PDF toggle
  initializePDFToggle();
});
