export function setupHistorySearch() {
    const searchInput = document.getElementById("searchInput");
    const historyList = document.getElementById("historyList");
  
    if (!searchInput || !historyList) {
      console.warn("Search elements missing");
      return;
    }
  
    const items = historyList.getElementsByClassName("history-item");
    let originalItems = Array.from(items);
  
    // Focus effects
    searchInput.addEventListener("focus", () => 
      document.querySelector(".cyber-search-container").classList.add("active")
    );
    
    searchInput.addEventListener("blur", () => 
      document.querySelector(".cyber-search-container").classList.remove("active")
    );
  
    // Search functionality
    searchInput.addEventListener("input", function() {
      const filter = this.value.toLowerCase();
      let visibleCount = 0;
      
      originalItems.forEach(item => {
        const match = item.textContent.toLowerCase().includes(filter);
        item.style.display = match ? "" : "none";
        if (match) visibleCount++;
      });
  
      // Handle no results
      const existingNoResults = document.querySelector(".no-results");
      if (visibleCount === 0 && filter.length > 0) {
        if (!existingNoResults) {
          const noResults = document.createElement("div");
          noResults.className = "no-results";
          noResults.textContent = "No matches found";
          historyList.appendChild(noResults);
        }
      } else if (existingNoResults) {
        existingNoResults.remove();
      }
    });
  }