# ``SDKSimpleJailbreakGuard``

Detecta indicios configurables de jailbreak en iPhone y iPad.

## Uso

Seleccioná un perfil y ejecutá el análisis de forma asíncrona:

```swift
let report = await JailbreakGuard(configuration: .fridaOnly).scan()

if report.isJailbroken {
    print(report.findings)
}
```

Cada ``JailbreakCheckResult`` diferencia entre una detección, un resultado limpio,
un check omitido y uno que no pudo evaluarse.

## Topics

### Análisis

- ``JailbreakGuard``
- ``JailbreakGuardConfiguration``
- ``JailbreakCheck``
- ``JailbreakReport``
- ``JailbreakCheckResult``
- ``JailbreakFinding``
