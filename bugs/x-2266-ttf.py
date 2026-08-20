# Payload
Fuente TTF craftada (fuente_maliciosa.ttf) con, según el vector a
demostrar:

Vector 1 (cmap formato 4): tabla cmap con múltiples segmentos de rango
amplio (startCount/endCount separados al máximo posible, repetido en
muchos segmentos).

Vector 2 (cmap formato 12): un único grupo con
  startCharCode = 0
  endCharCode  = 0xFFFFFFFF
(12 bytes de datos de grupo, ~4.294 millones de iteraciones resultantes).

Vector 3 (glifos compuestos circulares): dos glifos compuestos A y B,
donde A referencia a B como componente y B referencia a A como
componente (~28 bytes de datos de glifo).

Invocación:
add_font(family, style, fname='fuente_maliciosa.ttf', uni=True)
# y/o generación de texto con subseteo (makeSubset()) usando esa fuente

# Response
Vectores 1/2: agotamiento de CPU/memoria observado durante el parseo de
la tabla cmap, sin límite de tiempo ni de recursos aplicado por la
librería.

Vector 3: RecursionError sin control, propagado sin manejo explícito
desde getGlyphs().
