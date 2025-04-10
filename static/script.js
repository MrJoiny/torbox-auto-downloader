document.addEventListener('DOMContentLoaded', () => {
    const torrentsTbody = document.getElementById('torrents-tbody');
    const usenetTbody = document.getElementById('usenet-tbody');
    const loadingMessage = document.getElementById('loading-message');
    const errorMessage = document.getElementById('error-message');

    // --- Helper Functions ---
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0 || !bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function displayError(message) {
        errorMessage.textContent = `Error: ${message}`;
        errorMessage.style.display = 'block';
        loadingMessage.style.display = 'none';
    }

    // --- Populate Table ---
    function populateTable(tbody, items) {
        tbody.innerHTML = ''; // Clear existing rows
        if (!items || items.length === 0) {
            const row = tbody.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 6; // Span across all columns (Name, Status, Progress, Size, Date, Action)
            cell.textContent = 'No items found.';
            cell.style.textAlign = 'center';
            cell.style.fontStyle = 'italic';
            return;
        }

        items.forEach(item => {
            const row = tbody.insertRow();
            row.insertCell().textContent = item.name || 'N/A';
            row.insertCell().textContent = item.status || 'N/A';
            row.insertCell().textContent = `${(item.progress || 0).toFixed(1)}%`;
            row.insertCell().textContent = formatBytes(item.size);

            // Add and format the date cell
            const dateCell = row.insertCell();
            if (item.created_at) {
                try {
                    const date = new Date(item.created_at);
                    // Format as YYYY-MM-DD HH:MM
                    const year = date.getFullYear();
                    const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
                    const day = String(date.getDate()).padStart(2, '0');
                    const hours = String(date.getHours()).padStart(2, '0');
                    const minutes = String(date.getMinutes()).padStart(2, '0');
                    dateCell.textContent = `${year}-${month}-${day} ${hours}:${minutes}`;
                } catch (e) {
                    console.warn("Could not parse date:", item.created_at, e);
                    dateCell.textContent = 'Invalid Date';
                }
            } else {
                dateCell.textContent = 'N/A';
            }


            const actionCell = row.insertCell();
            const trackButton = document.createElement('button');
            trackButton.textContent = 'Track';
            trackButton.dataset.id = item.id;
            trackButton.dataset.type = item.type;
            trackButton.dataset.name = item.name;
            trackButton.dataset.hash = item.hash || ''; // Store hash if available
            actionCell.appendChild(trackButton);
        });
    }

    // --- Fetch Downloads ---
    async function fetchDownloads() {
        loadingMessage.style.display = 'block';
        errorMessage.style.display = 'none';
        torrentsTbody.innerHTML = ''; // Clear tables while loading
        usenetTbody.innerHTML = '';

        try {
            const response = await fetch('/api/downloads');
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            const data = await response.json();

            const torrents = data.filter(item => item.type === 'torrent');
            const usenet = data.filter(item => item.type === 'usenet');

            populateTable(torrentsTbody, torrents);
            populateTable(usenetTbody, usenet);

            loadingMessage.style.display = 'none';

        } catch (error) {
            console.error('Error fetching downloads:', error);
            displayError(error.message || 'Could not fetch download lists.');
        }
    }

    // --- Track Item ---
    async function trackItem(button) {
        const id = button.dataset.id;
        const type = button.dataset.type;
        const name = button.dataset.name;
        const hash = button.dataset.hash; // Get hash from dataset

        if (!id || !type || !name) {
            console.error('Missing data attributes on button:', button);
            displayError('Could not track item: missing data.');
            return;
        }

        button.disabled = true;
        button.textContent = 'Tracking...';
        errorMessage.style.display = 'none'; // Hide previous errors

        try {
            const response = await fetch('/api/track', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ id, type, name, hash }), // Include hash in payload
            });

            const result = await response.json();

            if (!response.ok) {
                // Use specific error from API if available, otherwise generic
                throw new Error(result.error || `Failed to track item (Status: ${response.status})`);
            }

            console.log('Track request successful:', result);
            button.textContent = 'Tracking Initiated'; // Keep disabled to prevent re-clicks for now
            // Optionally, provide more feedback or refresh list after a delay

        } catch (error) {
            console.error('Error tracking item:', error);
            displayError(error.message || 'Could not send track request.');
            button.disabled = false; // Re-enable button on error
            button.textContent = 'Track';
        }
    }

    // --- Event Listeners ---
    // Use event delegation for track buttons
    torrentsTbody.addEventListener('click', (event) => {
        if (event.target.tagName === 'BUTTON' && event.target.textContent === 'Track') {
            trackItem(event.target);
        }
    });

    usenetTbody.addEventListener('click', (event) => {
        if (event.target.tagName === 'BUTTON' && event.target.textContent === 'Track') {
            trackItem(event.target);
        }
    });

    // --- Initial Load ---
    fetchDownloads();
});
