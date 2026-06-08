# MickyAc Pro - Architecture Document

## 1. VisiÃ³n General

**MickyAc Pro** es una suite forense profesional para Windows 10/11 desarrollada en C# .NET 9 con WPF y MVVM.
Proporciona anÃ¡lisis completo de artefactos del sistema, detecciÃ³n de IOCs, generaciÃ³n de reportes y cadena de custodia.

## 2. Arquitectura (Clean Architecture)

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                     WPF (Presentation)                       â”‚
â”‚              Views / ViewModels / Controls                    â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                   Application Layer                           â”‚
â”‚         Services / Use Cases / DTOs / Mappings                â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                    Domain Layer                               â”‚
â”‚      Models / Enums / Interfaces / ValueObjects               â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                 Infrastructure Layer                          â”‚
â”‚  Parsers / Repositories / Data / Engines / Reporting          â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## 3. Diagrama de MÃ³dulos

```
MickyAc Pro
â”œâ”€â”€ Core
â”‚   â”œâ”€â”€ Domain Models (Evidencia, Caso, Artefacto, Timeline)
â”‚   â”œâ”€â”€ Enums (TipoArtefacto, EstadoCaso, NivelRiesgo)
â”‚   â””â”€â”€ Interfaces (IParser, IRepository, IReportService)
â”‚
â”œâ”€â”€ Parsers Forenses (20 mÃ³dulos)
â”‚   â”œâ”€â”€ AmcacheParser         â”œâ”€â”€ BAMParser
â”‚   â”œâ”€â”€ PrefetchParser        â”œâ”€â”€ USNParser
â”‚   â”œâ”€â”€ MFTParser             â”œâ”€â”€ SRUMParser
â”‚   â”œâ”€â”€ EventLogParser        â”œâ”€â”€ RegistryParser
â”‚   â”œâ”€â”€ BrowserParser         â”œâ”€â”€ PowerShellParser
â”‚   â”œâ”€â”€ ServicesParser        â”œâ”€â”€ TaskSchedulerParser
â”‚   â”œâ”€â”€ StartupParser         â”œâ”€â”€ USBParser
â”‚   â””â”€â”€ NetworkParser
â”‚
â”œâ”€â”€ Engines
â”‚   â”œâ”€â”€ TimelineEngine        â”œâ”€â”€ IOCEngine
â”‚   â”œâ”€â”€ YARAEngine            â””â”€â”€ CorrelationEngine
â”‚
â”œâ”€â”€ Services
â”‚   â”œâ”€â”€ ScanService           â”œâ”€â”€ EvidenceManager
â”‚   â”œâ”€â”€ ReportGenerator       â”œâ”€â”€ LogService
â”‚   â””â”€â”€ ExportService
â”‚
â””â”€â”€ UI (WPF MVVM)
    â”œâ”€â”€ Dashboard             â”œâ”€â”€ ScanManager
    â”œâ”€â”€ TimelineExplorer      â”œâ”€â”€ ArtifactExplorer
    â”œâ”€â”€ IOCManager            â”œâ”€â”€ YARAManager
    â”œâ”€â”€ Reports               â””â”€â”€ Settings
```

## 4. Flujo de Datos

```
Disco (NTFS) â†’ Parsers â†’ Artefactos â†’ Timeline Engine â†’ Timeline Unificada
                                      â†’ IOC Engine    â†’ Alertas
                                      â†’ Evidence Mgr  â†’ Cadena de Custodia
                                      â†’ Report Gen    â†’ PDF/HTML/CSV/JSON
```

## 5. TecnologÃ­as

- **.NET 9** - Framework base
- **WPF** - UI con MVVM (CommunityToolkit.Mvvm)
- **SQLite** (Microsoft.Data.Sqlite) - Base de datos local
- **Entity Framework Core** - ORM
- **Newtonsoft.Json** - SerializaciÃ³n JSON
- **QuestPDF** - GeneraciÃ³n PDF
- **Yara.NET** - Motor YARA
- **Microsoft.Extensions.DependencyInjection** - DI
- **Serilog** - Logging estructurado
- **LiveChartsCore** - GrÃ¡ficos dashboard

## 6. Estructura de Carpetas

```
src/
â”œâ”€â”€ MickyAc.Domain/          # Capa de dominio
â”œâ”€â”€ MickyAc.Application/     # Capa de aplicaciÃ³n
â”œâ”€â”€ MickyAc.Infrastructure/  # Capa de infraestructura
â””â”€â”€ MickyAc.WPF/            # Capa de presentaciÃ³n
tests/
â””â”€â”€ MickyAc.Tests/          # Tests unitarios
docs/
â””â”€â”€ ARCHITECTURE.md                     # Este documento
```
