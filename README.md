# Sega Model 1 Ghidra Analysis Package
Este paquete contiene herramientas, scripts y módulos de procesador para analizar juegos de la placa arcade **Sega Model 1** (como *Virtua Fighter*) en **Ghidra**.

La placa Sega Model 1 utiliza un microprocesador principal **NEC V60 (uPD70615)** y un DSP coprocesador geométrico **Fujitsu MB86233 (TGP)**.

---

## 📂 Contenido del Paquete

El paquete se organiza de la siguiente manera:

*   **`processors/`**
    *   **`V60/`**: Módulo de extensión de procesador para la CPU principal **NEC V60** de 32 bits (Little Endian).
    *   **`MB86233/`**: Módulo de extensión de procesador para el coprocesador geométrico **TGP** (Fujitsu MB86233).
*   **`scripts/`**
    *   **`model1_machine.py`**: Script de automatización en Python (Machine Builder) que realiza lo siguiente:
        1. Ensambla y deinterleavea (entrelaza a nivel de 16 bits) las ROMs de Virtua Fighter en un único binario plano de memoria mapeando las regiones correctas de CPU (incluyendo ROMs extendidas de datos MPR hasta un espacio de 20MB).
        2. Compila los ficheros de especificación Sleigh (`.slaspec`) para ambos procesadores en Ghidra.
        3. Invoca a Ghidra en modo headless para realizar el análisis de forma automatizada y exportar el código decompilado.
    *   **`Model1VFAnalysis.py`**: Script de post-análisis ejecutado dentro de Ghidra. Realiza lo siguiente:
        1. Mapea y etiqueta los registros de hardware y regiones de I/O específicos de Sega Model 1 en la imagen de memoria.
        2. Registra programáticamente los tipos de datos estructurados de geometría 3D en Ghidra: `Vector3D` (x, y, z), `Vector4D` (x, y, z, r), `Vertex3D` (pos, normal, color, u, v) y `TGP_Command`.
        3. Identifica los punteros de la tabla de vectores a modelos 3D en `0x200000`, etiquetándolos en la imagen de memoria para evitar análisis erróneo de datos como instrucciones de código.
        4. Realiza el recorrido del control flow de inicialización del boot y exporta toda la decompilación a un fichero fuente en C limpio.

---

## 🛠️ Requisitos e Instalación

### 1. Copiar los procesadores a Ghidra
Mueve las carpetas de procesadores a la instalación de Ghidra de tu sistema:

```bash
cp -R processors/V60 <GHIDRA_INSTALL_DIR>/Ghidra/Processors/
cp -R processors/MB86233 <GHIDRA_INSTALL_DIR>/Ghidra/Processors/
```

*Por ejemplo, en MacOS con Homebrew Cask, el directorio de destino suele ser:*
`/opt/homebrew/Caskroom/ghidra/X.X.X/ghidra_X.X.X_PUBLIC/Ghidra/Processors/`

### 2. Configurar el script de ejecución
Abre el script `scripts/model1_machine.py` y edita la sección de **Configuration** al principio del archivo con las rutas de tu sistema:

```python
ROM_DIR     = "/ruta/a/tus/roms/de/virtua_fighter"
GHIDRA_HOME = "/ruta/a/tu/ghidra"
```

*   `ROM_DIR` debe apuntar al directorio que contiene las ROMs originales del juego (e.g., `epr-16082.14`, `epr-16083.15`, `epr-16080.4`, `epr-16081.5`, etc.).
*   `GHIDRA_HOME` debe ser la ruta raíz de tu instalación de Ghidra.

---

## 🚀 Cómo Ejecutar el Análisis

Una vez configurado, ejecuta el script `model1_machine.py` desde tu terminal:

```bash
python3 scripts/model1_machine.py
```

El script imprimirá información detallada de cada paso del proceso:
1.  **Ensamblado de la memoria**: Intercalado a 16 bits de las ROMs principales (`epr-16082/3`) en la dirección `0x200000`, carga de las ROMs de arranque y mapeo de las ROMs extendidas (`mpr-16084` al `mpr-16091`) en los bancos de memoria superiores, formando una imagen unificada de 20MB.
2.  **Compilación Sleigh**: Se compilarán los ficheros `v60.slaspec` y `mb86233.slaspec` en tu instalación de Ghidra para asegurar que los cambios estén listos.
3.  **Headless Analysis**: Se iniciará Ghidra en segundo plano, se importará la imagen de memoria y se ejecutará el script de análisis de Ghidra.
4.  **Resultados**: Se generará la salida de decompilación en C del boot en `/tmp/model1_vf/model1_vf_decompiled.c`, y el informe de análisis general en `/tmp/model1_vf/analysis_output.txt`.

---

## 💡 Detalles Técnicos Adicionales
*   **Vector4D (x,y,z,r)**: Definido como una estructura de 16 bytes que contiene campos de tipo `float` para coordenadas X, Y, Z y un campo `r` que representa el radio / escala / valor homogéneo de la proyección geométrica del TGP.
*   **Gestión de Vectores de Datos**: El análisis automático en Ghidra está configurado para no confundir la tabla de vectores 3D del juego en `0x200000` con código ejecutable de la CPU, previniendo falsos desensamblados (`halt_baddata`) en el visor de Ghidra.
