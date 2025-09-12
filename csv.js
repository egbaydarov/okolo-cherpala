(() => {
window.App = window.App || {};
const AppNS = window.App;

AppNS.tableToCsv = function tableToCsv() {
  const rows = [];
  rows.push(['Channel', 'Msg ID', 'Date', 'Text', 'Link']);
  const trs = AppNS.dom.rows.querySelectorAll('tr');
  for (const tr of trs) {
    const channel = tr.children[0]?.textContent?.trim() || '';
    const id = tr.children[1]?.textContent?.trim() || '';
    const date = tr.children[2]?.textContent?.trim() || '';
    const text = tr.children[3]?.textContent?.trim() || '';
    const link = tr.children[4]?.querySelector('a')?.href || '';
    rows.push([channel, id, date, text, link]);
  }
  const csv = rows.map(r => r.map(v => {
    const s = String(v).replace(/"/g, '""');
    return `"${s}"`;
  }).join(',')).join('\n');
  return csv;
};
})();


