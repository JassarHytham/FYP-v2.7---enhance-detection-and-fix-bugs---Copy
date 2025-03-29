document.addEventListener("DOMContentLoaded", function() {
    const searchInput = document.getElementById("searchInput");
    const historyList = document.getElementById("historyList");
    const items = historyList.getElementsByClassName("history-item");
  
    // Add focus effect for search input
    searchInput.addEventListener("focus", function() {
      document.querySelector(".cyber-search-container").classList.add("active");
    });
  
    searchInput.addEventListener("blur", function() {
      document.querySelector(".cyber-search-container").classList.remove("active");
    });
  
    // Search functionality
    searchInput.addEventListener("keyup", function() {
      const filter = searchInput.value.toLowerCase();
      let hasVisibleItems = false;
      
      Array.from(items).forEach(function(item) {
        const text = item.textContent.toLowerCase();
        if (text.includes(filter)) {
          item.style.display = "";
          hasVisibleItems = true;
        } else {
          item.style.display = "none";
        }
      });
  
      // Show "no results" message if needed
      const noResults = document.querySelector(".no-results");
      if (!hasVisibleItems && filter.length > 0) {
        if (!noResults) {
          const noResultsMsg = document.createElement("div");
          noResultsMsg.className = "no-results";
          noResultsMsg.style.color = "var(--cyber-text)";
          noResultsMsg.textContent = "No matching reports found";
          historyList.appendChild(noResultsMsg);
        }
      } else if (noResults) {
        noResults.remove();
      }
    });
  });