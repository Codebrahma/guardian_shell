// Guardian Shell Dashboard — SSE event handler for index page
// htmx SSE extension processes events from /events/stream and calls this
// to render each event as a table row.

document.body.addEventListener('sse:event', function(evt) {
  // This is handled by htmx SSE extension on the index page.
  // The events page uses Alpine.js for more control.
});

// Custom htmx SSE message handler: render event JSON as a table row
htmx.defineExtension('guardian-sse', {});

// Override the default sse swap to render our JSON events as table rows
document.addEventListener('htmx:sseMessage', function(e) {
  if (e.detail.type !== 'event') return;
  try {
    const data = JSON.parse(e.detail.data);
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-50 text-sm';

    const time = new Date(data.timestamp);
    const timeStr = time.toLocaleTimeString() + '.' + String(time.getMilliseconds()).padStart(3, '0');

    const sevClass = {
      'info': 'severity-info',
      'warning': 'severity-warning',
      'critical': 'severity-critical'
    }[data.severity] || '';

    const actClass = {
      'allow': 'action-allow',
      'deny': 'action-deny',
      'blocked': 'action-blocked'
    }[data.action] || '';

    row.innerHTML = `
      <td class="px-4 py-1.5 text-gray-600 whitespace-nowrap text-xs">${timeStr}</td>
      <td class="px-4 py-1.5 whitespace-nowrap"><span class="text-xs font-medium ${sevClass}">${data.severity}</span></td>
      <td class="px-4 py-1.5 text-gray-700 text-sm">${data.agent_name}</td>
      <td class="px-4 py-1.5 text-gray-600 text-xs">${data.event_type}</td>
      <td class="px-4 py-1.5 whitespace-nowrap"><span class="text-xs font-medium ${actClass}">${data.action}</span></td>
      <td class="px-4 py-1.5 text-gray-700 text-xs font-mono truncate max-w-xs" title="${data.path}">${data.path}</td>
    `;

    const tbody = document.getElementById('recent-events');
    if (tbody) {
      // Remove "waiting" placeholder
      const placeholder = tbody.querySelector('td[colspan]');
      if (placeholder) placeholder.closest('tr').remove();

      tbody.prepend(row);
      // Keep only last 50 events
      while (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastElementChild);
      }
    }
  } catch(err) {}
});
