# CHANGELOG — MICKY.AC DFIR Platform

## [2.0.0] — 2026-06-08

### Added
- **Dashboard sections (14):** Overview, Sessions, Timeline, Registry, Processes, Services, Drivers, FileSystem, Event Logs, Network, Security, Threat Indicators, Raw JSON (syntax highlighting), Reports, Admin Panel
- **Timeline Engine:** Unified forensic timeline with category/source/severity filtering
- **Risk Engine:** LOW/MEDIUM/HIGH/CRITICAL classification with color-coded badges
- **Raw JSON viewer:** Syntax highlighting with collapsible tree view
- **Export:** JSON and CSV export with preview
- **Scan animations:** Analysis sweep line, connected node pulse indicators in WPF scanner
- **MICKY.AC logo:** logo.jpg served from web root, displayed in auth screen and sidebar
- **Persistence support:** Scanner modules for Startup Folder, Scheduled Tasks, WMI

### Changed
- **Full rebrand:** ForensicAnalyzerPro → MICKY.AC across all 6 .csproj/.slnx files (renamed on disk)
- **Validation system:** PIN validation via `/api/validate-pin` + `/api/use-pin` (JSON served from web)
- **Scanner modules expanded:** 10 → 24 modules, 14 → 49 artifact phases
- **Dashboard:** Complete rewrite with DFIR theme (black/red/neon), professional enterprise style
- **API:** New endpoints (`/data/pins.json`, `/data/results.json`, `/api/use-pin`, `/api/admin/*`)
- **Auth:** Master PIN 1188 grants admin access; X-Admin-Pin header for admin API
- **package.json names:** `mickyac-api`, `mickyac-dashboard-server`

### Fixed
- `.csproj` filename mismatch (disk had ForensicAnalyzerPro.*.csproj, references expected MickyAc.*.csproj)
- Dashboard login error handler variable scoping bug
- Netlify redirects for `/data/*` → function config now includes `path: ['/api/*', '/data/pins.json', '/data/results.json']`

### Removed
- All `localhost` / `127.0.0.1` references from server.js
- ForensicAnalyzerPro from all source file names
- Old localStorage-only PIN registration (now creates server-side PINs)

### Files Modified (22)
```
A  favicon.ico
A  logo.jpg
M  CHANGELOG.md
M  dashboard/deploy-vps.sh
M  dashboard/package.json
M  dashboard/server.js
M  index.html
M  netlify.toml
M  netlify/functions/api.mjs
M  package.json
M  src/MickyAc.WPF/MainWindow.xaml
M  src/MickyAc.WPF/Models/PinValidationResult.cs
M  src/MickyAc.WPF/Services/ApiService.cs
M  src/MickyAc.WPF/ViewModels/ScannerViewModel.cs
R  ForensicAnalyzerPro.slnx → MickyAc.slnx
R  src/MickyAc.Application/ForensicAnalyzerPro.Application.csproj → MickyAc.Application.csproj
R  src/MickyAc.Domain/ForensicAnalyzerPro.Domain.csproj → MickyAc.Domain.csproj
R  src/MickyAc.Infrastructure/ForensicAnalyzerPro.Infrastructure.csproj → MickyAc.Infrastructure.csproj
R  src/MickyAc.WPF/ForensicAnalyzerPro.WPF.csproj → MickyAc.WPF.csproj
R  tests/MickyAc.Tests/ForensicAnalyzerPro.Tests.csproj → MickyAc.Tests.csproj
M  package-lock.json
M  .github/workflows/deploy.yml
```
