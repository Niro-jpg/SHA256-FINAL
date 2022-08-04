# SHA256-FINAL

Questo è una versione più o meno reversibile di SHA256. 
Esistono 3 versioni differenti di codice tutte e 3 presenti nella stessa cartella.

-sha256.cpp: è una versione del codice resa reversibile con un simil complete logging
-sha2562.cpp: versione con alcune ottimizzazioni del file sha256.cpp
-sha2563.cpp: versione finale con una gestione differente dell'algoritmo, più semplice di quella originale 

# Per eseguire

- Digitare nella cartella SHA256-FINAL "g++ sha256.cpp main.cpp -o sha256_example" per compilare
- Digitare successivamente "./sha256_example" per eseguire
- Divertirti

per compilare versioni differenti dell'algoritmo si può scrivere nella linea di comanda il nome del file da voler compilare
-esempio: "g++ sha2563.cpp main3.cpp -o sha256_example" per compilare la versione finale dell'algoritmo

# Avvertenze

Attualmente il progetto è ancora in lavorazione ed infatti per cambiare input bisogna modificare per forza il codice.  
Ci sono ancora delle piccole cose non reversibili tipo i puntatori  ma appena potrò cercherò di cambiare ed aggiustare il tutto.

