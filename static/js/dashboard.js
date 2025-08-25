/**
 * Creates a stacked bar chart on a given canvas element.
 * @param {string} canvasId The ID of the canvas element.
 * @param {string} apiUrl The API endpoint to fetch data from.
 * @param {string} titleText The title to display for the chart.
 */
function createStackedBarChart(canvasId, apiUrl, titleText) {
    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return;
            const ctx = canvas.getContext('2d');

            // Check if there's any data to display by summing all data points.
            const total = data.datasets.reduce((sum, dataset) => sum + dataset.data.reduce((s, v) => s + v, 0), 0);

            if (data.labels.length === 0 || total === 0) {
                // If no data, display a message instead of an empty chart.
                canvas.parentElement.innerHTML = '<div class="text-center text-muted p-5">No data available to display.</div>';
                return;
            }

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels,
                    datasets: data.datasets.map(dataset => ({
                        ...dataset,
                    }))
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: titleText
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return '$' + value.toLocaleString();
                                }
                            }
                        }
                    },
                }
            });
        });
}

// This function runs when the dashboard page is loaded
document.addEventListener('DOMContentLoaded', function () {
    createStackedBarChart(
        'revenueByUnitChart',
        '/api/revenue-by-unit-quarter',
        'Projected Revenue (Revenue * Conversion %)'
    );

    createStackedBarChart(
        'revenueByOriginatingTypeChart',
        '/api/revenue-by-originating-type',
        'Projected Revenue by Originating Type (Grouped by Unit)'
    );
});