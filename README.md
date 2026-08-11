# Writeups & Rapports d'Audit | TryHackMe / HackTheBox

Ce repo regroupe mes writeups de CTF (TryHackMe, HackTheBox) ainsi que des rapports d'audit formels rédigés à partir de certaines de ces rooms.

## Pourquoi deux formats ?

Chaque room complétée donne lieu à un **writeup**, et certaines rooms, sélectionnées pour la richesse de leur chaîne d'exploitation, donnent lieu en plus à un **rapport d'audit** au format professionnel.

|              | Writeup                                                                          | Rapport d'audit                                                                        |
| ------------ | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Langue**   | Anglais                                                                          | Français                                                                               |
| **Ton**      | Personnel, narratif, première personne                                           | Formel, factuel, impersonnel                                                           |
| **Public**   | Communauté technique, autres hackers                                             | Recruteur, manager, client fictif                                                      |
| **Objectif** | Partager mon raisonnement réel, y compris les impasses et les moments de blocage | S'entraîner à la rédaction professionnelle et à la structuration d'un livrable d'audit |

Le rapport d'audit n'est pas fait systématiquement pour chaque room, seulement pour celles qui s'y prêtent (plusieurs vulnérabilités chaînées, une vraie chaîne d'exploitation à documenter).

## Structure du repo

```
.
├── Tryhackme/
│   ├── breaking-rsa/
│   │   ├── writeup.md
│   │   └── images/
│   ├── sqhell/
│   │   ├── writeup.md
│   │   └── images/
│   └── thats-the-ticket/
│       ├── writeup.md
│       └── images/
└── HTB/
    └── ...
```

## Index des writeups

| Room                                                       | Plateforme | Difficulté | Writeup | Rapport d'audit |
| ---------------------------------------------------------- | ---------- | ---------- | ------- | --------------- |
| [Breaking RSA](Tryhackme/breaking-rsa/writeup.md)          | TryHackMe  | Medium     | ✅      | —               |
| [SQHell](Tryhackme/sqhell/writeup.md)                      | TryHackMe  | Medium     | ✅      | —               |
| [That's The Ticket](Tryhackme/thats-the-ticket/writeup.md) | TryHackMe  | Medium     | ✅      | —               |

## Avertissement

Les flags sont remplacés par `REDACTED` dans les writeups et rapports publiés ici, afin de ne pas nuire à l'expérience d'autres apprenants sur ces rooms. Une version complète (avec flags) est conservée en local, hors de ce repo. Aucune IP réelle de machine cible n'est divulguée.
