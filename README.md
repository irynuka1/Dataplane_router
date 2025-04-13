Coitu Sebastian-Teodor 324CA

# README – Dataplane Router

În acest proiect se implementează dataplane-ul unui router, abordând principalele mecanisme de forwarding IPv4, ARP și generare de mesaje ICMP descrise în cadrul laboratoarelor de PCom. Implementarea se bazează pe un set de API-uri furnizate (ex.: `recv_from_any_link`, `send_to_link`, `read_rtable`, etc.) și pe manipularea directă a cadrelor Ethernet, pachetelor IP, mesajelor ARP și ICMP.

---

## Prezentare generală

Proiectul îndeplinește următoarele cerințe:

- **Forwarding IPv4:** Recepționarea cadrelor Ethernet, parsarea header-elor IP, verificarea integrității (checksum) și a valorii TTL, precum și decrementarea acestuia înainte de trimiterea pachetului pe interfața de ieșire.
- **Longest Prefix Match (LPM):** Găsirea celei mai potrivite intrări în tabela de rutare folosind binary search pe un vector de intrări sortat descrescător după prefix și mască.
- **Protocolul ARP:** Găsirea adresei MAC a următorului hop prin trimiterea ARP request-urilor și procesarea ARP reply-urilor, cu menținerea unui cache local. Pachetele ce nu pot fi trimise imediat sunt puse într-o coadă.
- **Protocolul ICMP:** Generarea mesajelor de răspuns (Echo Reply pentru pachetele destinate routerului) și a mesajelor de eroare (Time Exceeded pentru pachete cu TTL expirat sau Destination Unreachable pentru lipsa unei rute).

---

## Structuri de date utilizate

- **Structurile:** **`ether_hdr`**, **`ip_hdr`**, **`arp_hdr`**, **`icmp_hdr`**, care au fost deja implementate în scheletul temei.

- **Tabele:**
  - **Tabela de rutare (`routing_entries`):** Reprezentată printr-un vector de structuri `route_table_entry` alocat dinamic cu dimensiunea standard de 100k elemente.
  - **Tabela ARP (`arp_entries`):** Gestionată dinamic într-un vector de structuri `arp_table_entry`.

- **Coadă de pachete:**  
  Pachetele care așteaptă ARP-ul sunt plasate într-o coadă `packet_queue` (folosind funcționalitatea din `queue.h`). Se stochează metadate suplimentare în `METADATA` (dimensiunea pachetului, interfața de ieșire și adresa IP a următorului hop) pentru a reconstitui cadrul la trimitere.

---

## Procesarea pachetelor

1. **Recepția cadrelor:**
   - Bucla din `main()` apelează funcția `recv_from_any_link` pentru a primi cadre Ethernet de pe oricare interfață.

2. **Determinarea tipului de pachet:**
   - Funcția `handle_packet` inspectează câmpul `ethr_type` din header-ul Ethernet:
     - Pentru cadre IPv4 (`0x0800`), se apelează `route_ip_packet`.
     - Pentru cadre ARP (`0x0806`), se procesează cu `arp_req_handler` sau `arp_rep_handler` în funcție de opcode.

3. **IP forwarding – făcut aproape complet în laboratorul 4:**
   - Se verifică dacă pachetul IP este destinat direct routerului sau dacă trebuie trimis mai departe.
   - Se validează integritatea pachetului prin calculul checksum-ului și se decrementează TTL-ul. Dacă acesta este prea mic, se generează un mesaj ICMP "Time Exceeded".
   - Se caută intrarea corespunzătoare în tabela de rutare folosind funcția `route_lookup` (Longest Prefix Match).

4. **ARP:**
   - Dacă nu există o intrare ARP pentru următorul hop, pachetul este pus în coadă (`enqueue_arp`) și se generează un ARP Request (`create_arp_req`).
   - La primirea unui ARP Reply (`arp_rep_handler`), tabela ARP este actualizată și pachetele din coadă, aflate în așteptarea unei rezoluții ARP, sunt retransmise.

5. **Generarea mesajelor ICMP (`handle_icmp`):**
   - Pentru pachetele destinate routerului, se generează mesaje de tip Echo Reply.
   - Pentru erori (TTL expirat sau lipsa unui next hop), se generează mesaje ICMP de tip "Time Exceeded" sau "Destination Unreachable".

---

## Detalii de implementare

### Gestionarea TTL și Checksum

- **`reduce_ttl`:**  
  Decrementează valoarea TTL din header-ul IP și actualizează checksum-ul, ținând cont de schimbarea efectuată.

- **`set_broadcast_mac`:**  
  Setează un vector de 6 octeți la valoarea `0xFF`, reprezentând adresa MAC de destinație ca fiind broadcast.

### Căutarea în tabela de rutare (Longest Prefix Match)

- **`cmp_routing_entries`:**  
  Funcția folosită de `qsort` pentru sortarea intrărilor din tabela de rutare. Se ordonează descrescător după valoarea prefixului și a măștii (după conversia în host order), pentru a facilita căutările.

- **`route_lookup`:**  
  Utilizează o căutare binară pe vectorul sortat pentru a găsi intrarea cu cea mai specifică mască care se potrivește cu adresa de destinație din pachet.

---

## Concluzie

Această temă a constituit o completare a laboratoarelor, contribuind la aprofundarea cunoștințelor despre rețele la nivel practic. Prin implementarea codului, am reușit să înțeleg fiecare detaliu esențial al funcționării rețelelor, la nivelul predat până în acest moment. Am structurat codul într-un mod modular și am adăugat comentarii sugestive, pentru o înțelegere cât mai clară și intuitivă a implementării. În plus, enunțul temei a fost foarte descriptiv, iar materialele explicative oferite au fost de mare ajutor.
