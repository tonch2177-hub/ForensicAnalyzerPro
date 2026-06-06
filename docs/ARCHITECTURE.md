# ForensicAnalyzer Pro - Architecture Document

## 1. Visión General

**ForensicAnalyzer Pro** es una suite forense profesional para Windows 10/11 desarrollada en C# .NET 9 con WPF y MVVM.
Proporciona análisis completo de artefactos del sistema, detección de IOCs, generación de reportes y cadena de custodia.

## 2. Arquitectura (Clean Architecture)

```
┌─────────────────────────────────────────────────────────────┐
│                     WPF (Presentation)                       │
│              Views / ViewModels / Controls                    │
├─────────────────────────────────────────────────────────────┤
│                   Application Layer                           │
│         Services / Use Cases / DTOs / Mappings                │
├─────────────────────────────────────────────────────────────┤
│                    Domain Layer                               │
│      Models / Enums / Interfaces / ValueObjects               │
├─────────────────────────────────────────────────────────────┤
│                 Infrastructure Layer                          │
│  Parsers / Repositories / Data / Engines / Reporting          │
└─────────────────────────────────────────────────────────────┘
```

## 3. Diagrama de Módulos

```
ForensicAnalyzer Pro
├── Core
│   ├── Domain Models (Evidencia, Caso, Artefacto, Timeline)
│   ├── Enums (TipoArtefacto, EstadoCaso, NivelRiesgo)
│   └── Interfaces (IParser, IRepository, IReportService)
│
├── Parsers Forenses (20 módulos)
│   ├── AmcacheParser         ├── BAMParser
│   ├── PrefetchParser        ├── USNParser
│   ├── MFTParser             ├── SRUMParser
│   ├── EventLogParser        ├── RegistryParser
│   ├── BrowserParser         ├── PowerShellParser
│   ├── ServicesParser        ├── TaskSchedulerParser
│   ├── StartupParser         ├── USBParser
│   └── NetworkParser
│
├── Engines
│   ├── TimelineEngine        ├── IOCEngine
│   ├── YARAEngine            └── CorrelationEngine
│
├── Services
│   ├── ScanService           ├── EvidenceManager
│   ├── ReportGenerator       ├── LogService
│   └── ExportService
│
└── UI (WPF MVVM)
    ├── Dashboard             ├── ScanManager
    ├── TimelineExplorer      ├── ArtifactExplorer
    ├── IOCManager            ├── YARAManager
    ├── Reports               └── Settings
```

## 4. Flujo de Datos

```
Disco (NTFS) → Parsers → Artefactos → Timeline Engine → Timeline Unificada
                                      → IOC Engine    → Alertas
                                      → Evidence Mgr  → Cadena de Custodia
                                      → Report Gen    → PDF/HTML/CSV/JSON
```

## 5. Tecnologías

- **.NET 9** - Framework base
- **WPF** - UI con MVVM (CommunityToolkit.Mvvm)
- **SQLite** (Microsoft.Data.Sqlite) - Base de datos local
- **Entity Framework Core** - ORM
- **Newtonsoft.Json** - Serialización JSON
- **QuestPDF** - Generación PDF
- **Yara.NET** - Motor YARA
- **Microsoft.Extensions.DependencyInjection** - DI
- **Serilog** - Logging estructurado
- **LiveChartsCore** - Gráficos dashboard

## 6. Estructura de Carpetas

```
src/
├── ForensicAnalyzerPro.Domain/          # Capa de dominio
├── ForensicAnalyzerPro.Application/     # Capa de aplicación
├── ForensicAnalyzerPro.Infrastructure/  # Capa de infraestructura
└── ForensicAnalyzerPro.WPF/            # Capa de presentación
tests/
└── ForensicAnalyzerPro.Tests/          # Tests unitarios
docs/
└── ARCHITECTURE.md                     # Este documento
```
