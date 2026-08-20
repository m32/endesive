'''
# Dowód (odczyt kodu + dowód koncepcji konstrukcji wiadomości)
Potwierdzono w endesive/email/verify.py:8-38, że pętla w msg.walk()
przypisuje zmienną `plain` tylko wtedy, gdy ct == 'text/plain', i że żadna
inna gałąź kodu nie zbiera ani nie uwzględnia zawartości
części text/html lub załączników w obliczeniach skrótu.

# Przetestuj konstrukcję wiadomości (ten sam podpisujący, ten sam oryginalny tekst jawny
z dodatkową niepodpisaną częścią text/html)
1. Zacznij od poprawnej wiadomości S/MIME multipart/signed, podpisanej nad
częścią text/plain o nieszkodliwej zawartości.

2. Dodaj dodatkową część text/html o innej zawartości do tej samej wiadomości MIME,
bez modyfikowania oryginalnej części text/plain ani
podpisu.

3. Wywołaj endesive.email.verify(data) dla zmodyfikowanej wiadomości.

# Wynik
hashok/signatureok pozostają wartością True (sprawdzane tylko w odniesieniu do oryginalnego, nienaruszonego tekstu/zwykłej części), podczas gdy wiadomość zawiera dodatkową treść (tekst/html), która w ogóle nie została zweryfikowana.
'''
