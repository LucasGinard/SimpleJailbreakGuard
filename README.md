# SDKSimpleJailbreakGuard

SDK Swift configurable para detectar indicios de jailbreak en iPhone y iPad con iOS 15 o superior. Funciona offline y no recolecta datos.

## Detecciones

- Binarios `su`, `sudo` y shells rootful/rootless.
- Frida Server/Gadget mediante archivos, dylibs, entorno y puertos locales.
- Cydia, Sileo, Zebra, Installer y Saily.
- Artefactos de apt/dpkg/SSH y rutas como `/var/jb`.
- Substrate, Substitute, libhooker y ElleKit.
- Escritura fuera del sandbox.

## Uso

```swift
import SDKSimpleJailbreakGuard

let report = await JailbreakGuard(configuration: .all).scan()
if report.isJailbroken {
    print(report.findings)
}
```

Para ejecutar una sola categoría:

```swift
let frida = await JailbreakGuard(configuration: .fridaOnly).scan()
let stores = await JailbreakGuard(configuration: .suspiciousStoresOnly).scan()
```

También se puede construir una configuración con `enabledChecks`, `additionalPaths`, `additionalStoreSchemes` y `fridaPorts`.

Para consultar tiendas, la app anfitriona debe declarar en `LSApplicationQueriesSchemes`: `cydia`, `sileo`, `zbra`, `installer` y `saily`.

## XCFramework

```bash
./scripts/build-xcframework.sh
```

El resultado queda en `build/SDKSimpleJailbreakGuard.xcframework` e incluye dispositivo `arm64` y Simulator `arm64`/`x86_64`. Arrastralo al proyecto consumidor y seleccioná **Embed & Sign**.

La app SwiftUI incluida en `Example/` muestra cómo elegir perfiles y presentar el informe.

> La detección es de mejor esfuerzo. Una app iOS no puede observar literalmente que otro proceso ejecute `sudo su`, y un jailbreak avanzado puede ocultar o modificar señales. En Simulator los checks se omiten por defecto para evitar falsos positivos.
