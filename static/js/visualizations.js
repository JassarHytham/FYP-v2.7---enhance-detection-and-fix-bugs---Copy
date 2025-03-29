// visualizations.js
// Contains all functions related to fetching data and rendering the visualizations. This file will be used to create the timeline, protocol distribution chart, and network topology visualization.
const d3 = window.d3;
const Plotly = window.Plotly;

// Error handler for visualization fetching
export function handleVisualizationError(error) {
    console.error('Error:', error);
    d3.select("#protocolChart").html("Error loading visualization data");
    d3.select("#topologyViz").html("Error loading network topology");
  }
  
  // Unified loadVisualizations function
  export function loadVisualizations(reportFilename) {
    // Clear all containers first with loading messages
    d3.select("#timelineViz").html("Loading timeline...");
    d3.select("#topologyViz").html("Loading network topology...");
    d3.select("#protocolChart").html("Loading protocol chart...");

    // Show loading spinner
    const spinner = d3.select("#visualizations")
        .append("div")
        .attr("class", "spinner")
        .html('<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>');

    // Fetch visualization data
    fetch(`/get_visualization_data?report=${encodeURIComponent(reportFilename)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) throw data.error;
            
            // Remove spinner
            spinner.remove();
            
            // Create visualizations
            createTimeline(data.timeline_data || []);
            createProtocolChart(data.protocol_distribution || {});
            createTopology(data.topology_data?.nodes || [], data.topology_data?.links || []);
        })
        .catch(error => {
            spinner.remove();
            handleVisualizationError(error);
            
            // Show specific error messages in each container
            d3.select("#timelineViz").html("Failed to load timeline data");
            d3.select("#topologyViz").html("Failed to load network topology");
            d3.select("#protocolChart").html("Failed to load protocol chart");
            
            console.error('Visualization error:', error);
        });
}
  
  export function createTimeline(aggregatedData) {
    // Clear previous visualization
    d3.select("#timelineViz").html("");
    
    if (!aggregatedData || aggregatedData.length === 0) {
        d3.select("#timelineViz").html("No timeline data available");
        return;
    }

    // Set dimensions
    const margin = { top: 20, right: 30, bottom: 40, left: 60 };
    const width = 800 - margin.left - margin.right;
    const height = 300 - margin.top - margin.bottom;

    // Create SVG container
    const svg = d3.select("#timelineViz")
        .append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

    // Parse timestamps - handle both ISO format and custom formats
    const parseTime = (timestamp) => {
        try {
            // Try ISO format first
            return new Date(timestamp);
        } catch (e) {
            // Fallback to custom format if needed
            const parts = timestamp.split(/[- :]/);
            return new Date(parts[0], parts[1]-1, parts[2], parts[3], parts[4]);
        }
    };

    // Format data
    const data = aggregatedData.map(d => ({
        date: parseTime(d.timestamp),
        count: d.count
    })).filter(d => !isNaN(d.date.getTime())); // Filter out invalid dates

    if (data.length === 0) {
        d3.select("#timelineViz").html("No valid timeline data");
        return;
    }

    // Create scales
    const xScale = d3.scaleTime()
        .domain(d3.extent(data, d => d.date))
        .range([0, width]);

    const yScale = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.count)])
        .nice()
        .range([height, 0]);

    // Create axes
    svg.append("g")
        .attr("transform", `translate(0,${height})`)
        .call(d3.axisBottom(xScale).ticks(5).tickFormat(d3.timeFormat("%H:%M")));

    svg.append("g")
        .call(d3.axisLeft(yScale).ticks(5));

    // Create line generator
    const line = d3.line()
        .x(d => xScale(d.date))
        .y(d => yScale(d.count))
        .curve(d3.curveMonotoneX);

    // Draw line
    svg.append("path")
        .datum(data)
        .attr("fill", "none")
        .attr("stroke", "#00f3ff")
        .attr("stroke-width", 2)
        .attr("d", line);

    // Add gradient fill
    const area = d3.area()
        .x(d => xScale(d.date))
        .y0(yScale(0))
        .y1(d => yScale(d.count))
        .curve(d3.curveMonotoneX);

    svg.append("path")
        .datum(data)
        .attr("fill", "url(#gradient)")
        .attr("d", area);

    // Add gradient definition
    svg.append("defs").append("linearGradient")
        .attr("id", "gradient")
        .attr("gradientUnits", "userSpaceOnUse")
        .attr("x1", 0)
        .attr("y1", yScale(0))
        .attr("x2", 0)
        .attr("y2", yScale(d3.max(data, d => d.count)))
        .selectAll("stop")
        .data([
            { offset: "0%", color: "#00f3ff", opacity: 0.3 },
            { offset: "100%", color: "#0a0a1a", opacity: 0 }
        ])
        .enter().append("stop")
        .attr("offset", d => d.offset)
        .attr("stop-color", d => d.color)
        .attr("stop-opacity", d => d.opacity);

    // Add dots for data points
    svg.selectAll(".dot")
        .data(data)
        .enter().append("circle")
        .attr("class", "dot")
        .attr("cx", d => xScale(d.date))
        .attr("cy", d => yScale(d.count))
        .attr("r", 3)
        .attr("fill", "#00f3ff");
}
  
export function createProtocolChart(protocolData) {
  const container = d3.select("#protocolChart");
  container.html(""); // Clear previous content
  
  // Ensure we have valid data
  if (!protocolData || Object.keys(protocolData).length === 0) {
      container.html('<div class="no-data">No protocol data available</div>');
      return;
  }

  // Prepare Plotly data
  const data = [{
      values: Object.values(protocolData),
      labels: Object.keys(protocolData),
      type: 'pie',
      hole: 0.4,
      textinfo: 'percent+label',
      insidetextorientation: 'radial',
      marker: {
          colors: ['#00f3ff', '#4CAF50', '#FF5722', '#9C27B0', '#FFC107', '#607D8B'],
          line: {
              color: '#0a0a1a',
              width: 1
          }
      }
  }];

  const layout = {
      margin: { t: 30, b: 30, l: 30, r: 30 },
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      font: { color: '#ffffff' },
      showlegend: true,
      legend: {
          orientation: 'h',
          y: -0.2
      }
  };

  const config = {
      responsive: true,
      displayModeBar: false
  };

  // Ensure container is visible and has dimensions
  container.style('height', '400px')
           .style('width', '100%')
           .style('visibility', 'visible');

  // Create the chart
  Plotly.newPlot('protocolChart', data, layout, config)
      .then(() => {
          // Force a redraw after rendering
          setTimeout(() => Plotly.Plots.resize('protocolChart'), 100);
      })
      .catch(err => {
          console.error('Plotly error:', err);
          container.html(`<div class="error">Chart error: ${err.message}</div>`);
      });
}
export function createTopology(nodes, links) {
  d3.select("#topologyViz").html("");
    
  // Handle case where we only have aggregate counts
  if (nodes.length === 2 && links.length === 1 && 
      nodes.some(n => n.id.includes("Source"))) {
      
      const summary = `Network Activity:
          ${links[0].value} packets between
          ${nodes[0].id} and ${nodes[1].id}`;
          
      d3.select("#topologyViz")
          .append("div")
          .attr("class", "topology-summary")
          .html(summary);
      return;
  }

  const width = 800, height = 400;
  const svg = d3.select("#topologyViz")
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", [0, 0, width, height])
      .attr("preserveAspectRatio", "xMidYMid meet");

  // Create a group for zoom/pan
  const g = svg.append("g");

  // Add zoom/pan behavior
  const zoom = d3.zoom()
      .scaleExtent([0.5, 5])
      .on("zoom", (event) => {
          g.attr("transform", event.transform);
      });

  svg.call(zoom);

  // Create force simulation
  const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(d => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(20));

  // Create links
  const link = g.append("g")
      .selectAll("line")
      .data(links)
      .enter().append("line")
      .attr("stroke", "#00f3ff")
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.6);

  // Create nodes
  const node = g.append("g")
      .selectAll("circle")
      .data(nodes)
      .enter().append("circle")
      .attr("r", 10)
      .attr("fill", d => {
          // Color nodes based on their role (you can customize this)
          return d.id.includes('192.168') ? '#4CAF50' : '#FF5722';
      })
      .attr("stroke", "#ffffff")
      .attr("stroke-width", 1.5)
      .call(d3.drag()
          .on("start", dragstarted)
          .on("drag", dragged)
          .on("end", dragended));

  // Add labels
  const label = g.append("g")
      .selectAll("text")
      .data(nodes)
      .enter().append("text")
      .text(d => d.id)
      .attr("font-family", "monospace")
      .attr("fill", "#ffffff")
      .attr("font-size", "10px")
      .attr("dx", 12)
      .attr("dy", 4);

  // Add tooltips
  node.append("title")
      .text(d => `IP: ${d.id}`);

  simulation.on("tick", () => {
      link
          .attr("x1", d => d.source.x)
          .attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x)
          .attr("y2", d => d.target.y);

      node
          .attr("cx", d => d.x)
          .attr("cy", d => d.y);

      label
          .attr("x", d => d.x)
          .attr("y", d => d.y);
  });

  function dragstarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
  }

  function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
  }

  function dragended(event) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
  }
}