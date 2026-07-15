# Βιβλιογραφία — Επαληθευμένες αναφορές για τη διπλωματική

> Όλες οι αναφορές επαληθεύτηκαν (2026-07-02) μέσω επίσημων πηγών (IEEE Xplore,
> ACM DL, USENIX, Springer, Wiley) — τα DOI είναι ενεργά. Δίπλα σε κάθε αναφορά
> σημειώνεται ΠΟΥ χρησιμοποιείται στο κείμενο (βλ. `sdn_architecture_justification.md`
> και `thesis_outline.md`).

## Θεμελιώδεις αναφορές SDN / OpenFlow

**[1] Kreutz, D., Ramos, F. M. V., Veríssimo, P. E., Rothenberg, C. E., Azodolmolky, S., & Uhlig, S. (2015).**
Software-Defined Networking: A Comprehensive Survey. *Proceedings of the IEEE*, 103(1), 14–76.
DOI: [10.1109/JPROC.2014.2371999](https://doi.org/10.1109/JPROC.2014.2371999)
→ *Χρήση:* Κεφ. 2 — ορισμός SDN, οι «τέσσερις πυλώνες» (διαχωρισμός planes, λογικά κεντρικοποιημένος έλεγχος, προγραμματισιμότητα). Η πιο έγκυρη επισκόπηση του πεδίου (>10.000 ετεροαναφορές).

**[2] McKeown, N., Anderson, T., Balakrishnan, H., Parulkar, G., Peterson, L., Rexford, J., Shenker, S., & Turner, J. (2008).**
OpenFlow: Enabling Innovation in Campus Networks. *ACM SIGCOMM Computer Communication Review*, 38(2), 69–74.
DOI: [10.1145/1355734.1355746](https://doi.org/10.1145/1355734.1355746)
→ *Χρήση:* Κεφ. 2 — το ιδρυτικό paper του OpenFlow· flow tables, match-action, flow stats.

**[3] Benzekki, K., El Fergougui, A., & Elbelrhiti Elalaoui, A. (2017).**
Software-Defined Networking (SDN): A Survey. *Security and Communication Networks*, 9(18), 5803–5833.
DOI: [10.1002/sec.1737](https://doi.org/10.1002/sec.1737)
→ *Χρήση:* Κεφ. 2–3 — προκλήσεις SDN (scalability, dependability, ασφάλεια)· υποστηρίζει το επιχείρημα για τον controller ως bottleneck/single point of failure.

## Εργαλεία πειραματικής διάταξης

**[4] Lantz, B., Heller, B., & McKeown, N. (2010).**
A Network in a Laptop: Rapid Prototyping for Software-Defined Networks. *Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks (HotNets-IX)*, Article 19.
DOI: [10.1145/1868447.1868466](https://doi.org/10.1145/1868447.1868466)
→ *Χρήση:* Κεφ. 5.2 — το paper του Mininet (ACM SIGCOMM Test of Time Award).

**[5] Pfaff, B., Pettit, J., Koponen, T., Jackson, E., Zhou, A., Rajahalme, J., Gross, J., Wang, A., Stringer, J., Shelar, P., Amidon, K., & Casado, M. (2015).**
The Design and Implementation of Open vSwitch. *12th USENIX Symposium on Networked Systems Design and Implementation (NSDI 15)*, 117–130.
[usenix.org/conference/nsdi15/technical-sessions/presentation/pfaff](https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/pfaff)
→ *Χρήση:* Κεφ. 5.2 — αρχιτεκτονική του OVS (Best Paper NSDI'15)· τεκμηριώνει ότι το OVS είναι πλήρες OpenFlow switch και τη χρήση `ovs-ofctl` ως πρότυπης διεπαφής.

## Ασφάλεια SDN & επιθέσεις

**[6] Scott-Hayward, S., Natarajan, S., & Sezer, S. (2016).**
A Survey of Security in Software Defined Networks. *IEEE Communications Surveys & Tutorials*, 18(1), 623–654.
DOI: [10.1109/COMST.2015.2453114](https://doi.org/10.1109/COMST.2015.2453114)
→ *Χρήση:* Κεφ. 3 — επιφάνεια επίθεσης ανά plane, DoS στον controller, control channel saturation. Τεκμηριώνει και το σκεπτικό του υβριδικού μοντέλου (§5.x): η εξάρτηση του forwarding από τον controller αυξάνει το ρίσκο.

**[7] Braga, R., Mota, E., & Passito, A. (2010).**
Lightweight DDoS Flooding Attack Detection Using NOX/OpenFlow. *IEEE 35th Conference on Local Computer Networks (LCN 2010)*, 408–415.
DOI: [10.1109/LCN.2010.5735752](https://doi.org/10.1109/LCN.2010.5735752)
→ *Χρήση:* Κεφ. 3–4 — η κλασική πρώτη εργασία ανίχνευσης DDoS με flow features σε SDN controller· άμεσα συγγενής με τη δική σου προσέγγιση (flow stats → features → ML), ιδανική για σύγκριση.

## Μηχανική μάθηση για ανίχνευση

**[8] Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008).**
Isolation Forest. *2008 Eighth IEEE International Conference on Data Mining (ICDM)*, 413–422.
DOI: [10.1109/ICDM.2008.17](https://doi.org/10.1109/ICDM.2008.17)
→ *Χρήση:* Κεφ. 4–5 — το ιδρυτικό paper του αλγορίθμου που χρησιμοποιείς· γραμμική πολυπλοκότητα, καταλληλότητα για anomaly detection χωρίς ετικέτες.

**[9] Sultana, N., Chilamkurti, N., Peng, W., & Alhadad, R. (2019).**
Survey on SDN Based Network Intrusion Detection System Using Machine Learning Approaches. *Peer-to-Peer Networking and Applications*, 12(2), 493–501.
DOI: [10.1007/s12083-017-0630-0](https://doi.org/10.1007/s12083-017-0630-0)
→ *Χρήση:* Κεφ. 4 — επισκόπηση ML-based IDS σε SDN· πλαισιώνει τη δική σου συνεισφορά.

**[10] Elsayed, M. S., Le-Khac, N.-A., & Jurcut, A. D. (2020).**
InSDN: A Novel SDN Intrusion Dataset. *IEEE Access*, 8, 165263–165284.
DOI: [10.1109/ACCESS.2020.3022633](https://doi.org/10.1109/ACCESS.2020.3022633)
→ *Χρήση:* Κεφ. 4, 5.1 — το dataset του offline ML pipeline (Μέθοδος Β)· γιατί είναι ειδικό για SDN.

---

## BibTeX (έτοιμο για LaTeX / Zotero / Mendeley import)

```bibtex
@article{kreutz2015sdn,
  author  = {Kreutz, Diego and Ramos, Fernando M. V. and Ver{\'i}ssimo, Paulo Esteves and Rothenberg, Christian Esteve and Azodolmolky, Siamak and Uhlig, Steve},
  title   = {Software-Defined Networking: A Comprehensive Survey},
  journal = {Proceedings of the IEEE},
  year    = {2015},
  volume  = {103},
  number  = {1},
  pages   = {14--76},
  doi     = {10.1109/JPROC.2014.2371999}
}

@article{mckeown2008openflow,
  author  = {McKeown, Nick and Anderson, Tom and Balakrishnan, Hari and Parulkar, Guru and Peterson, Larry and Rexford, Jennifer and Shenker, Scott and Turner, Jonathan},
  title   = {OpenFlow: Enabling Innovation in Campus Networks},
  journal = {ACM SIGCOMM Computer Communication Review},
  year    = {2008},
  volume  = {38},
  number  = {2},
  pages   = {69--74},
  doi     = {10.1145/1355734.1355746}
}

@article{benzekki2017survey,
  author  = {Benzekki, Kamal and El Fergougui, Abdeslam and Elbelrhiti Elalaoui, Abdelbaki},
  title   = {Software-Defined Networking ({SDN}): A Survey},
  journal = {Security and Communication Networks},
  year    = {2017},
  volume  = {9},
  number  = {18},
  pages   = {5803--5833},
  doi     = {10.1002/sec.1737}
}

@inproceedings{lantz2010mininet,
  author    = {Lantz, Bob and Heller, Brandon and McKeown, Nick},
  title     = {A Network in a Laptop: Rapid Prototyping for Software-Defined Networks},
  booktitle = {Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks (HotNets-IX)},
  year      = {2010},
  articleno = {19},
  doi       = {10.1145/1868447.1868466}
}

@inproceedings{pfaff2015ovs,
  author    = {Pfaff, Ben and Pettit, Justin and Koponen, Teemu and Jackson, Ethan and Zhou, Andy and Rajahalme, Jarno and Gross, Jesse and Wang, Alex and Stringer, Joe and Shelar, Pravin and Amidon, Keith and Casado, Martin},
  title     = {The Design and Implementation of {Open vSwitch}},
  booktitle = {12th USENIX Symposium on Networked Systems Design and Implementation (NSDI 15)},
  year      = {2015},
  pages     = {117--130},
  url       = {https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/pfaff}
}

@article{scotthayward2016security,
  author  = {Scott-Hayward, Sandra and Natarajan, Sriram and Sezer, Sakir},
  title   = {A Survey of Security in Software Defined Networks},
  journal = {IEEE Communications Surveys \& Tutorials},
  year    = {2016},
  volume  = {18},
  number  = {1},
  pages   = {623--654},
  doi     = {10.1109/COMST.2015.2453114}
}

@inproceedings{braga2010lightweight,
  author    = {Braga, Rodrigo and Mota, Edjard and Passito, Alexandre},
  title     = {Lightweight {DDoS} Flooding Attack Detection Using {NOX}/{OpenFlow}},
  booktitle = {IEEE 35th Conference on Local Computer Networks (LCN 2010)},
  year      = {2010},
  pages     = {408--415},
  doi       = {10.1109/LCN.2010.5735752}
}

@inproceedings{liu2008isolation,
  author    = {Liu, Fei Tony and Ting, Kai Ming and Zhou, Zhi-Hua},
  title     = {Isolation Forest},
  booktitle = {2008 Eighth IEEE International Conference on Data Mining (ICDM)},
  year      = {2008},
  pages     = {413--422},
  doi       = {10.1109/ICDM.2008.17}
}

@article{sultana2019survey,
  author  = {Sultana, Nasrin and Chilamkurti, Naveen and Peng, Wei and Alhadad, Rabei},
  title   = {Survey on {SDN} Based Network Intrusion Detection System Using Machine Learning Approaches},
  journal = {Peer-to-Peer Networking and Applications},
  year    = {2019},
  volume  = {12},
  number  = {2},
  pages   = {493--501},
  doi     = {10.1007/s12083-017-0630-0}
}

@article{elsayed2020insdn,
  author  = {Elsayed, Mahmoud Said and Le-Khac, Nhien-An and Jurcut, Anca Delia},
  title   = {{InSDN}: A Novel {SDN} Intrusion Dataset},
  journal = {IEEE Access},
  year    = {2020},
  volume  = {8},
  pages   = {165263--165284},
  doi     = {10.1109/ACCESS.2020.3022633}
}

@article{hamarshe2023ddos,
  author  = {Hamarshe, Ahmad and Ashqar, Huthaifa I. and Hamarsheh, Mohammad},
  title   = {Detection of {DDoS} Attacks in Software Defined Networking Using Machine Learning Models},
  journal = {arXiv preprint arXiv:2303.06513},
  year    = {2023}
}

@article{gohari2024ctmbids,
  author  = {Jafari Gohari, Rasoul and Aliahmadipour, Laya and Kuchaki Rafsanjani, Marjan},
  title   = {{CTMBIDS}: Convolutional Tsetlin Machine Based Intrusion Detection System for {DDoS} Attacks in an {SDN} Environment},
  journal = {arXiv preprint arXiv:2409.03544},
  year    = {2024}
}

@article{he2023adversarial,
  author  = {He, Ke and Kim, Dan Dongseong and Asghar, Muhammad Rizwan},
  title   = {Adversarial Machine Learning for Network Intrusion Detection Systems: A Comprehensive Survey},
  journal = {IEEE Communications Surveys \& Tutorials},
  year    = {2023},
  volume  = {25},
  number  = {1},
  pages   = {538--566},
  doi     = {10.1109/COMST.2022.3233793}
}

@article{goldschmidt2025datasets,
  author  = {Goldschmidt, Patrik and Chud{\'a}, Daniela},
  title   = {Network Intrusion Datasets: A Survey, Limitations, and Recommendations},
  journal = {Computers \& Security},
  year    = {2025},
  volume  = {156},
  pages   = {104510},
  doi     = {10.1016/j.cose.2025.104510}
}

@article{janabi2024sdnids,
  author  = {Janabi, Ahmed H. and Kanakis, Triantafyllos and Johnson, Mark},
  title   = {Survey: Intrusion Detection System in Software-Defined Networking},
  journal = {IEEE Access},
  year    = {2024},
  volume  = {12},
  pages   = {164097--164120},
  doi     = {10.1109/ACCESS.2024.3493384}
}

@article{dogan2025sdnmitigation,
  author  = {Do{\u{g}}an, Sait Melih and Ko{\c{c}}ak, Aynur and Alkan, Mustafa},
  title   = {Detection and Mitigation of Cyber-Attacks in Software Defined Networks Using Machine Learning/Deep Learning: A Systematic Literature Review, Research Challenges and Future Directions},
  journal = {International Journal of Information Security},
  year    = {2025},
  volume  = {24},
  pages   = {209},
  doi     = {10.1007/s10207-025-01114-z}
}
```

## Πρόσφατες peer-reviewed πηγές 2023–2025 (επαληθευμένες μέσω Crossref)

**[26] He, K., Kim, D. D., & Asghar, M. R. (2023).** Adversarial Machine Learning for Network Intrusion Detection Systems: A Comprehensive Survey. *IEEE Communications Surveys & Tutorials*, 25(1), 538–566. DOI: [10.1109/COMST.2022.3233793](https://doi.org/10.1109/COMST.2022.3233793)
→ *Χρήση:* §6.12 — πλαισιώνει την ανάλυση αντίπαλης ευπάθειας/adversarial robustness.

**[27] Goldschmidt, P., & Chudá, D. (2025).** Network Intrusion Datasets: A Survey, Limitations, and Recommendations. *Computers & Security*, 156, 104510. DOI: [10.1016/j.cose.2025.104510](https://doi.org/10.1016/j.cose.2025.104510)
→ *Χρήση:* §6.6 — υποστηρίζει τη συζήτηση για διαρροή/διπλότυπα και τους περιορισμούς των συνόλων IDS.

**[28] Janabi, A. H., Kanakis, T., & Johnson, M. (2024).** Survey: Intrusion Detection System in Software-Defined Networking. *IEEE Access*, 12, 164097–164120. DOI: [10.1109/ACCESS.2024.3493384](https://doi.org/10.1109/ACCESS.2024.3493384)
→ *Χρήση:* §3.8 — σύγχρονη επισκόπηση ML-based IDS σε SDN.

**[29] Doğan, S. M., Koçak, A., & Alkan, M. (2025).** Detection and Mitigation of Cyber-Attacks in Software Defined Networks Using Machine Learning/Deep Learning: A Systematic Literature Review, Research Challenges and Future Directions. *International Journal of Information Security*, 24, 209. DOI: [10.1007/s10207-025-01114-z](https://doi.org/10.1007/s10207-025-01114-z)
→ *Χρήση:* §3.8 / Κεφ. 7 — ανίχνευση ΚΑΙ αντιμετώπιση σε SDN, άμεσα συναφές με τον τίτλο.
