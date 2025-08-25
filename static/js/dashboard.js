// This function runs when the dashboard page is loaded
document.addEventListener('DOMContentLoaded', function () {
    // Fetch data from our API endpoint
    fetch('/api/revenue-by-unit-quarter')
        .then(response => response.json())
        .then(data => {
            // Get the canvas element from the HTML
            const ctx = document.getElementById('revenueByUnitChart').getContext('2d');

            // Create a new bar chart
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels, // e.g., ["2024 Q1", "2024 Q2"]
                    datasets: data.datasets.map(dataset => ({
                        ...dataset,
                        // You can add specific styling for each dataset here
                    }))
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Projected Revenue (Revenue * Conversion %)'
                        }
                    },
                    scales: {
                        x: {
                            stacked: true, // Stack bars for the same quarter
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) { return '$' + value.toLocaleString(); }
                            }
                        }
                    }
                }
            });
        });
});