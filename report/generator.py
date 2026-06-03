import re
from datetime import datetime


LEVEL_COLORS = {
    'danger':     ('#ff4757', '#2d0a0e'),
    'suspicious': ('#ffa502', '#2d1f00'),
    'info':       ('#747d8c', '#1a1d23'),
    'clean':      ('#2ed573', '#0a1f12'),
}

LEVEL_ICONS = {
    'danger':     '&#9888;',
    'suspicious': '&#9888;',
    'info':       '&#8505;',
    'clean':      '&#10003;',
}

RISK_LABELS = {
    'clean':      ('ЧИСТО', '#2ed573'),
    'suspicious': ('ПОДОЗРИТЕЛЬНО', '#ffa502'),
    'danger':     ('ОПАСНОСТЬ', '#ff4757'),
    'unknown':    ('НЕИЗВЕСТНО', '#747d8c'),
}

_TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')

# Типы находок, которые означают фактический запуск чита
_EXEC_TYPES = {
    'bam_cheat_execution',
    'prefetch_cheat_exe',
    'prefetch_cheat_jar_path',
    'userassist_cheat',
    'appcompat_cheat',
    'shimcache_cheat',
}


class ReportGenerator:
    def __init__(self, results: dict, username: str):
        self.results   = results
        self.username  = username
        self.scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate(self) -> str:
        overall_risk  = self._calc_overall_risk()
        timeline      = self._build_timeline()
        last_run      = self._get_last_execution(timeline)
        summary_cards = self._render_summary_cards(last_run)
        timeline_html = self._render_timeline(timeline)
        sections_html = ''.join(
            self._render_section(name, data)
            for name, data in self.results.items()
        )
        risk_label, risk_color = RISK_LABELS.get(overall_risk, RISK_LABELS['unknown'])

        return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PT Check Report — {self.username}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #e6edf3;
    --text-dim: #8b949e;
    --danger:   #ff4757;
    --warn:     #ffa502;
    --ok:       #2ed573;
    --info:     #747d8c;
  }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px;
  }}
  .header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 6px; }}
  .header .meta {{ color: var(--text-dim); font-size: 13px; }}
  .header .meta span {{ margin-right: 20px; }}
  .overall-risk {{
    display: inline-block;
    padding: 6px 18px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 15px;
    margin-top: 12px;
    border: 2px solid {risk_color};
    color: {risk_color};
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 28px 40px; }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 14px;
    margin-bottom: 32px;
  }}
  .summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }}
  .summary-card .card-label {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }}
  .summary-card .card-value {{ font-size: 22px; font-weight: 700; }}
  .summary-card .card-value.small {{ font-size: 13px; font-weight: 600; font-family: 'Consolas', monospace; }}
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 18px;
    overflow: hidden;
  }}
  .section-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    cursor: pointer;
    user-select: none;
    transition: background 0.15s;
  }}
  .section-header:hover {{ background: rgba(255,255,255,0.03); }}
  .section-title {{ font-weight: 600; font-size: 15px; }}
  .section-desc {{ color: var(--text-dim); font-size: 12px; margin-top: 2px; }}
  .section-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 700;
    white-space: nowrap;
  }}
  .chevron {{ color: var(--text-dim); transition: transform 0.2s; font-size: 12px; margin-left: 10px; }}
  .section-body {{ padding: 0 20px 16px; border-top: 1px solid var(--border); }}
  .finding {{
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid rgba(48,54,61,0.5);
  }}
  .finding:last-child {{ border-bottom: none; }}
  .finding-icon {{
    width: 22px;
    height: 22px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    flex-shrink: 0;
    margin-top: 1px;
  }}
  .finding-content {{ flex: 1; min-width: 0; }}
  .finding-msg {{ font-weight: 500; margin-bottom: 3px; }}
  .finding-detail {{
    color: var(--text-dim);
    font-size: 12px;
    font-family: 'Consolas', 'Fira Code', monospace;
    background: rgba(0,0,0,0.3);
    border-radius: 4px;
    padding: 4px 8px;
    word-break: break-all;
    white-space: pre-wrap;
    margin-top: 4px;
  }}
  .tag-danger    {{ background: rgba(255,71,87,0.15);  color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }}
  .tag-suspicious{{ background: rgba(255,165,2,0.15);  color: #ffa502; border: 1px solid rgba(255,165,2,0.3); }}
  .tag-info      {{ background: rgba(116,125,140,0.15);color: #747d8c; border: 1px solid rgba(116,125,140,0.3); }}
  .tag-clean     {{ background: rgba(46,213,115,0.15); color: #2ed573; border: 1px solid rgba(46,213,115,0.3); }}
  .icon-danger    {{ background: rgba(255,71,87,0.2);  color: #ff4757; }}
  .icon-suspicious{{ background: rgba(255,165,2,0.2);  color: #ffa502; }}
  .icon-info      {{ background: rgba(116,125,140,0.2);color: #747d8c; }}
  .icon-clean     {{ background: rgba(46,213,115,0.2); color: #2ed573; }}
  .collapsed .section-body {{ display: none; }}
  .collapsed .chevron {{ transform: rotate(-90deg); }}
  /* ── Timeline ─────────────────────────────────────────────── */
  .timeline {{ position: relative; padding: 8px 0; }}
  .timeline::before {{
    content: '';
    position: absolute;
    left: 128px; top: 0; bottom: 0;
    width: 2px;
    background: var(--border);
  }}
  .tl-item {{
    display: flex;
    align-items: flex-start;
    padding: 7px 0;
  }}
  .tl-time {{
    width: 112px;
    text-align: right;
    font-size: 11px;
    color: var(--text-dim);
    padding-top: 3px;
    flex-shrink: 0;
    font-family: 'Consolas', monospace;
    line-height: 1.4;
  }}
  .tl-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
    margin: 4px 16px 0;
    position: relative;
    z-index: 1;
  }}
  .tl-content {{ flex: 1; }}
  .tl-msg {{ font-size: 13px; font-weight: 500; }}
  .tl-src {{ font-size: 11px; color: var(--text-dim); margin-top: 1px; }}
  footer {{
    text-align: center;
    color: var(--text-dim);
    font-size: 12px;
    padding: 24px 0 32px;
    border-top: 1px solid var(--border);
    margin-top: 8px;
  }}
</style>
</head>
<body>
<div class="header">
  <h1>&#128269; PT Check</h1>
  <div class="meta">
    <span>&#128100; Пользователь: <b>{self.username}</b></span>
    <span>&#128337; Время проверки: <b>{self.scan_time}</b></span>
  </div>
  <div class="overall-risk">{risk_label}</div>
</div>

<div class="container">
  <div class="summary-grid">
    {summary_cards}
  </div>
  {timeline_html}
  {sections_html}
</div>

<footer>PT Check &mdash; отчёт сгенерирован {self.scan_time}</footer>

<script>
  document.querySelectorAll('.section-header').forEach(function(header) {{
    header.addEventListener('click', function() {{
      header.closest('.section').classList.toggle('collapsed');
    }});
  }});
</script>
</body>
</html>"""

    def _calc_overall_risk(self):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2, 'unknown': -1}
        worst = 'clean'
        for data in self.results.values():
            r = data.get('risk', 'unknown')
            if order.get(r, -1) > order.get(worst, 0):
                worst = r
        return worst

    def _count_by_level(self, findings):
        counts = {'danger': 0, 'suspicious': 0, 'info': 0}
        for f in findings:
            level = f.get('level', 'info')
            if level in counts:
                counts[level] += 1
        return counts

    def _render_summary_cards(self, last_run: str | None = None):
        total_danger = 0
        total_suspicious = 0
        total_info = 0
        total_sections  = len(self.results)
        danger_sections = 0

        for data in self.results.values():
            findings = data.get('findings', [])
            counts   = self._count_by_level(findings)
            total_danger     += counts['danger']
            total_suspicious += counts['suspicious']
            total_info       += counts['info']
            if data.get('risk') == 'danger':
                danger_sections += 1

        cards = [
            ('Угрозы',     str(total_danger),    '#ff4757' if total_danger     > 0 else '#2ed573', False),
            ('Подозрений', str(total_suspicious), '#ffa502' if total_suspicious > 0 else '#2ed573', False),
            ('Инфо',       str(total_info),       '#747d8c', False),
            ('Разделов',   str(total_sections),   '#58a6ff', False),
            ('Опасных',    str(danger_sections),  '#ff4757' if danger_sections  > 0 else '#2ed573', False),
        ]
        if last_run:
            cards.append(('Последний запуск', last_run[:16], '#ff4757', True))

        html = ''
        for label, value, color, small in cards:
            size_cls = ' small' if small else ''
            html += f'''<div class="summary-card">
  <div class="card-label">{label}</div>
  <div class="card-value{size_cls}" style="color:{color}">{value}</div>
</div>'''
        return html

    # ── Timeline ──────────────────────────────────────────────────────────────

    def _build_timeline(self) -> list:
        events = []
        for scanner_key, data in self.results.items():
            scanner_name = data.get('name', scanner_key)
            for finding in data.get('findings', []):
                if finding.get('level') not in ('danger', 'suspicious'):
                    continue
                detail = finding.get('detail', '')
                m = _TS_RE.search(detail)
                if not m:
                    continue
                ts_str = m.group(1)
                try:
                    dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                events.append({
                    'dt':      dt,
                    'dt_str':  ts_str,
                    'message': finding.get('message', ''),
                    'level':   finding.get('level', 'info'),
                    'scanner': scanner_name,
                    'ftype':   finding.get('type', ''),
                })
        events.sort(key=lambda e: e['dt'], reverse=True)
        return events

    def _get_last_execution(self, events: list) -> str | None:
        for e in events:
            if e['ftype'] in _EXEC_TYPES:
                return e['dt_str']
        return None

    def _render_timeline(self, events: list) -> str:
        if not events:
            return ''

        dot_colors = {'danger': '#ff4757', 'suspicious': '#ffa502'}
        items_html = ''
        for e in events:
            color = dot_colors.get(e['level'], '#747d8c')
            msg = (e['message']
                   .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
            src = (e['scanner']
                   .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
            # Разбиваем timestamp на дату и время для двустрочного отображения
            ts_parts = e['dt_str'][:16].split(' ')
            ts_html  = f"{ts_parts[0]}<br><b>{ts_parts[1]}</b>" if len(ts_parts) == 2 else e['dt_str'][:16]
            items_html += f'''    <div class="tl-item">
      <div class="tl-time">{ts_html}</div>
      <div class="tl-dot" style="background:{color};box-shadow:0 0 5px {color}99"></div>
      <div class="tl-content">
        <div class="tl-msg">{msg}</div>
        <div class="tl-src">{src}</div>
      </div>
    </div>\n'''

        count     = len(events)
        badge_cls = 'tag-danger' if any(e['level'] == 'danger' for e in events) else 'tag-suspicious'

        return f'''<div class="section">
  <div class="section-header">
    <div>
      <div class="section-title">&#128197; Хронология событий</div>
      <div class="section-desc">Все находки с временными метками — от новых к старым</div>
    </div>
    <div style="display:flex;align-items:center;gap:8px">
      <span class="section-badge {badge_cls}">{count} событий</span>
      <span class="chevron">&#9660;</span>
    </div>
  </div>
  <div class="section-body">
    <div class="timeline">
{items_html}    </div>
  </div>
</div>'''

    # ── Sections ──────────────────────────────────────────────────────────────

    def _render_section(self, key, data):
        name     = data.get('name', key)
        desc     = data.get('description', '')
        findings = data.get('findings', [])
        risk     = data.get('risk', 'unknown')
        error    = data.get('error')

        risk_label, risk_color = RISK_LABELS.get(risk, RISK_LABELS['unknown'])
        badge_class = f'tag-{risk}' if risk in LEVEL_COLORS else 'tag-info'

        if error:
            findings_html = (
                f'<div class="finding"><div class="finding-icon icon-info">!</div>'
                f'<div class="finding-content"><div class="finding-msg">Ошибка сканера</div>'
                f'<div class="finding-detail">{error}</div></div></div>'
            )
        elif not findings:
            findings_html = (
                '<div class="finding"><div class="finding-icon icon-clean">&#10003;</div>'
                '<div class="finding-content"><div class="finding-msg" '
                'style="color:var(--text-dim)">Находок нет</div></div></div>'
            )
        else:
            findings_html = ''.join(self._render_finding(f) for f in findings)

        collapsed_class = '' if risk in ('danger', 'suspicious') else 'collapsed'

        return f'''<div class="section {collapsed_class}">
  <div class="section-header">
    <div>
      <div class="section-title">{name}</div>
      <div class="section-desc">{desc}</div>
    </div>
    <div style="display:flex;align-items:center;gap:8px">
      <span class="section-badge {badge_class}">{risk_label}</span>
      <span class="chevron">&#9660;</span>
    </div>
  </div>
  <div class="section-body">
    {findings_html}
  </div>
</div>'''

    def _render_finding(self, f):
        level      = f.get('level', 'info')
        msg        = f.get('message', '')
        detail     = f.get('detail', '')
        icon_html  = LEVEL_ICONS.get(level, '&#8505;')
        icon_class = f'icon-{level}'

        detail_html = ''
        if detail:
            escaped     = detail.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            detail_html = f'<div class="finding-detail">{escaped}</div>'

        return f'''<div class="finding">
  <div class="finding-icon {icon_class}">{icon_html}</div>
  <div class="finding-content">
    <div class="finding-msg">{msg}</div>
    {detail_html}
  </div>
</div>'''
