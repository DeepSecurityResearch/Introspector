<p align="center">
<img align="right" src="https://www.introspector.sh/assets/img/Introspector_Github_Banner.png" alt="Introspector Framework" />
</p>
&nbsp;

<div align="center">

 Readme: <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">`English`</a> / <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">`Spanish`</a> 


![Python](https://img.shields.io/badge/python-3.8+-blue)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docs](https://img.shields.io/badge/docs-introspector.sh-green)](https://introspector.sh)
</div>

---

## Introspector Framework 


Un framework de operaciones Out-of-Band (OOB) listo para usar. Diseñado para ser más que un servidor de callbacks, Introspector — **Analiza el comportamiento del cliente, evalúa la superficie de ataque y entrega exploits**.


<img align="right" src="https://www.introspector.sh/assets/img/introspector_server_start_carbon.png" height="310" alt="Introspector">


- Tracking de Callbacks HTTP/DNS
- Hosting de archivos simple.
- Arsenal de payloads OOB listo para usar.
- GEO IP y Whois pasivo.
- Reconocimiento de HTTP Requests.
- Fuzzing de HTTP Response.
- Explota Client-Side y Server-Side con una sola herramienta.
- Y mucho, mucho [más](https://www.introspector.sh/)...


Las capturas de pantalla están disponibles en los [Docs](https://introspector.sh/screenshots).


![Python](https://img.shields.io/badge/python-3.8+-blue)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docs](https://img.shields.io/badge/docs-introspector.sh-green)](https://introspector.sh)


## Capturas de Pantalla de Introspector

### Callbacks HTTP y DNS
*Introspector inicia servidores de callbacks HTTP y DNS para registrar las interacciones del objetivo, se muestra una bandera del país del servidor de origen para ayudar al tracking de interacciones. Introspector también tiene un botón de **whois** para mostrar información completa del objetivo.*

<img align="center" src="https://www.introspector.sh/assets/img/Screenshot-02.png" alt="Introspector HTTP and DNS Callback server">

---

### Análisis y Detección de SSRF con delay de respuesta controlado
*Si quieres estar seguro sobre la interacción de un backend, puedes usar Introspector para establecer un tiempo de respuesta específico.*

<img align="center" src="https://www.introspector.sh/assets/img/Screenshot-01.png" alt="Introspector">



&nbsp;


## El Concepto

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  OOB Tradicional:  "¿Recibí un callback?"      → Sí/No                      │
│                                                                             │
│  Introspector:     "¿Qué puedo aprender sobre este cliente?"                │
└─────────────────────────────────────────────────────────────────────────────┘

    Envías:       ?url=http://introspector.sh/anything
                              │
                              ▼
    Backend:      Hace fetch de /anything
                              │
                  Pero también hace auto-request de /robots.txt, /favicon.ico
                              │
                              ▼
    Introspector: Responde con redirect 302 estratégico
                              │
                ┌─────────────┴─────────────────┐
                ▼                               ▼
        Segunda request              Sin segunda request
        a /roboted.txt              
                │                               │
                ▼                               ▼
        ✓ Sigue redirects              ✗ No sigue
        → Bypass de SSRF viable        → Intenta otras técnicas
```

Rutas como `/robots.txt` y `/favicon.ico` son solicitadas **automáticamente** por browsers, crawlers y librerías HTTP. Al servir respuestas estratégicas, estás haciendo introspección del comportamiento del cliente de forma pasiva — desde la request #1.

---

## Inicio Rápido

```bash
git clone https://github.com/DeepSecurityResearch/Introspector.git
cd Introspector
pip3 install -r requirements.txt
sudo python3 Introspector.py
```

```
[introspector]> introspect enable follow-redirect
[+] Scan module 'follow-redirect' enabled

[introspector]> run create xxe1
[+] Created /run/a8x2k1.xml
```

---

## Características

| | Característica | Descripción |
|---|---------|-------------|
| 📡 | HTTP/DNS Listeners | Captura unificada de callbacks |
| 🔍 | Scanners Pasivos | Detecta comportamiento de redirects, thresholds de timeout |
| 🧬 | Arsenal de Payloads | XXE, SVG bombs, CSV injection, pixel floods |
| 📁 | File Hosting | Sirve cualquier archivo con MIME types correctos |
| 🎨 | Response Designer | Crea HTTP responses personalizadas |
| 🌍 | GeoIP + WHOIS | Intel en tiempo real de cada request |
| 💾 | Persistencia | Las sesiones sobreviven a reinicios |

---

## Documentación

Documentación completa, casos de uso y ejemplos en **[introspector.sh](https://introspector.sh)**

---

## Legal

**Solo para testing autorizado.**

---

<p align="center">
  <i>Construido para hunters.</i>
</p>
