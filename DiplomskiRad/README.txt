Preduslovi:
1. Fajl keystore.jks staviti u C:\sert\
2. U okruzenju dozvoliti paralelno izvrsavanje klasa Trustee i Voter

Uputstva za upotrebu:
1. Definisati pitanja u fajlu Questions.txt. Prva linija je ime izbora.
   Zatim za svako pitanje po dve linije, jedna za tekst pitanja, a druga za ponudjene odgovore(obavezno razdvojeni zarezom)
2. Definisati listu glasaca u fajlu Voters.txt. Za svakog glasaca 4 linije: id, password, email i name.
3. Definisati listu poverenika u fajlu Trustees.txt. Za svakog poverenika po dve linije: id, password.
4. Pokrenuti klasu Server.
5. Pokrenuti klasu Trustee onoliko puta koliko ima poverenika. Za svakog poverenika se ulogovati.
   To je sve sto je potrebno kod poverenika da se uradi. Kada se svaki poverenik uloguje, moze da se nastavi u sledecu fazu.
   Kada se svaki poverenik uloguje, izbori su spremni i glasaci mogu da se prikljuce i glasaju. Takodje se pokrece tajmer.
   Izbori su vremenski ograniceni i trajanje moze da se podesi promenljivom voteDurationInMinutes (default = 3).
6. Pokrenuti klasu Voter onoliko puta koliko ima glasaca (ili manje). Ulogovati se, popuniti pitanja.
   Kada se glas popuni, ispisuje se ballot tracker za njegov enkriptovani glas. Postavlja se izbor glasacu,
   moze da posalje svoj glas ili da proveri da li je ispravno sastavljen. Ako se proverava glas, glas se unistava i 
   klasa Glasac mora ponovo da se pokrene, glasac mora ponovo da se uloguje i popuni glas ispocetka.
7. Nakon isteka vremena za glasanje, izracunavaju se rezultati od pristiglih glasova i svi javni podaci su dostupni glasacu.
   Glasac ima meni sa opcijama za prikaz javnih podataka ili za provere.  

Kratko objasnjenje projekta:
1. U prvoj fazi svaki poverenik generise par tajni-privatni kljuc. Server skuplja ove parcijalne javne kljuceve i od
   njih mnozenjem pravi jedan (globalni)javni kljuc izbora. Poverenik takodje uz kljuc salje zero-knowledge proof da
   za javni kljuc koji salje zaista zna tajni kljuc. 
2. Glasaci enkriptuju glas koristeci javni kljuc izbora. Takodje generisu zero-knowledge proof da je glas ispravno sastavljen.
   Glasac dobija ballot tracker(hash glasa) nakon sto je enkriptovan i spreman za slanje. Glasac moze ili da posalje glas ili 
   da proveri da li taj glas zaista sadrzi ono sto je uneo. U tom slucaju se prikazuje sadrzaj glasa i daje mogucnost glasacu
   da sam proveri da li se ballot tracker poklapa sa onim sto je dobio, kao i da li je ispravno sastavljen. 
3. Nakon zatvaranja izbora za glasace, svi pristigli glasovi se homomorfno sabiraju na serveru i salju poverenicima da ih dekriptuju.
   Svaki poverenik dekriptuje rezultat, i serveru vraca svoju parcijalnu dekripciju, kao i dokaz da je dekripcija ispravna.
   Server od parcijalnih dekripcija formira konacan rezultat izbora u plaintext-u.
4. U cetvtoj fazi se vrsi provera korektnosti izbora. Glasaci mogu da provere da li im je glas uracunat, i da li su izbori
   korektno sracunati. To moze da uradi jer su podaci o izborima javno dostupni. (lista glasaca, lista poverenika, lista glasova, 
   opsti parametri izbora, enkriptovani rezultat, plaintext rezultat). Glasac ove podatke moze da izlista.

