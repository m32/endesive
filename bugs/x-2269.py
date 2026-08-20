# Payload
PDF cuyo diccionario /Outlines contiene un nodo cuyo /Next referencia a
un nodo anterior de la misma cadena, formando un ciclo (A -> B -> A ->
B -> ...) en vez de terminar en un nodo sin /Next.

Invocación:
PdfFileReader(pdf_data).getOutlines()
# o, sin cambiar ningún parámetro (comportamiento por defecto):
PdfFileMerger().append(pdf_data)

# Response
El proceso no retorna: el bucle "while True" en getOutlines() sigue la
cadena /Next indefinidamente, consumiendo CPU sin límite natural hasta
que algo externo (timeout de infraestructura, kill manual) lo detiene.
