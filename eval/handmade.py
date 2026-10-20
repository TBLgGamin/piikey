"""Builds eval/handmade.jsonl: realistic NL/EN/DE chatbot prompts with exact gold PII spans.

Items are written with inline marks, `[[LABEL:value]]`, so every gold span is right by
construction: the script strips the marks and records byte offsets into the UTF-8 text. Labels are
the coarse categories of eval/labels.toml ([source.handmade]). The set is exhaustive: every value a
careful annotator would mask is marked, so anything else a detector masks is a false positive.
Dates that are not birth dates, prices of products, model names, UUIDs in logs, ISO codes and
the like are deliberately left unmarked (hard negatives). Places and organizations are marked
when they say something about the people in the text (where someone lives, works, meets, was born);
general-knowledge mentions ('a poem about Amsterdam', 'an outage at KPN', 'the iPhone 15') are not.

Run: python eval/handmade.py   (stdlib only; rewrites eval/handmade.jsonl)
"""

import json
import re
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARK = re.compile(r"\[\[([A-Z_]+):(.+?)\]\]", re.S)

# (lang, marked text). Valid checksums where a real value would have one: IBANs pass mod-97,
# card numbers pass Luhn, BSNs pass the 11-proof.
ITEMS: list[tuple[str, str]] = [
    # --- English: everyday chatbot prompts -------------------------------------------------------
    ("en", "Can you write a polite reminder to [[PERSON:Sarah Thompson]] that her invoice is overdue? Her email is [[EMAIL:sarah.thompson@brightwave.co.uk]]."),
    ("en", "Rewrite this so it sounds friendlier: 'Dear [[PERSON:Mr. Patel]], your account [[ACCOUNT:AC-55821]] has been suspended.'"),
    ("en", "My name is [[PERSON:Daniel O'Connor]], I live at [[ADDRESS:14 Baker Street, London NW1 6XE]] and my phone is [[PHONE:+44 20 7946 0958]]."),
    ("en", "Summarise this email from [[PERSON:Emily Clarke]] ([[EMAIL:e.clarke@northgate-legal.com]]) about the contract with [[ORG:Northgate Legal LLP]]."),
    ("en", "I was born on [[DOB:12 March 1987]] in [[LOCATION:Manchester]]. Write a short bio for my LinkedIn."),
    ("en", "Please transfer the refund to [[FINANCIAL:GB29NWBK60161331926819]], account holder [[PERSON:James Whitfield]]."),
    ("en", "Why does my card [[FINANCIAL:4111 1111 1111 1111]] keep getting declined on the checkout page?"),
    ("en", "Fix this curl command: curl -H 'Authorization: Bearer [[SECRET:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U]]' https://api.example.com/v1/items"),
    ("en", "My SSN is [[ID_NUMBER:536-22-8714]], can you help me fill in the W-4 form?"),
    ("en", "The server at [[NETWORK:192.168.14.27]] stopped responding after the update to version 2.4.1 on 3 May."),
    ("en", "Draft a reply to [[PERSON:Rose]]: she asked whether the meeting on Friday can move to 10:30."),
    ("en", "I bought a dozen red roses and a bottle of Rosé for 24.99 dollars. Suggest a card message."),
    ("en", "What's the difference between gpt-4o and claude-3-5-sonnet for summarising PDFs?"),
    ("en", "Mark the tasks as done in the sprint board and move ticket ENG-1423 to review."),
    ("en", "[[PERSON:Mark Jensen]] asked me to forward the Q3 report to [[EMAIL:mark.jensen@fjordline-shipping.no]]."),
    ("en", "My patient [[PERSON:Linda Hall]] (DOB [[DOB:04/11/1962]]) was diagnosed with [[SENSITIVE:type 2 diabetes]] and started metformin."),
    ("en", "He told HR that he is a member of [[SENSITIVE:the Unite union]] and asked about strike pay."),
    ("en", "Write a cover letter for me: [[PERSON:Priya Raman]], [[PERSON_ATTR:senior data engineer]], [[EMAIL:priya.raman@outlook.com]], [[PHONE:(415) 555-0132]]."),
    ("en", "Log line: 2026-10-14T09:12:44Z INFO request_id=3f2b9c1e-8a4d-4f6b-9e21-7c5d0a9b1f33 status=200 latency=41ms"),
    ("en", "Our office moved to [[ADDRESS:500 Terry Francine Street, San Francisco, CA 94158]]. Update the footer text."),
    ("en", "Translate to French: 'Please call [[PERSON:Oliver Grant]] back on [[PHONE:07700 900461]] before 5pm.'"),
    ("en", "The wifi password is [[SECRET:Tr0ub4dor&3xK!]], can you make a printable sign for the guests?"),
    ("en", "Is ISO 27001 or SOC 2 more relevant for a SaaS company with 40 employees in the EU?"),
    ("en", "Here is my Stripe key [[SECRET:sk_live_51HqT9vKz8rB2xY7nQ4wL0pE3]] - why does the webhook return 401?"),
    ("en", "Our MAC filter blocks [[NETWORK:3C:22:FB:9A:41:07]], how do I whitelist it on a UniFi controller?"),
    ("en", "Write a birthday message for my colleague [[PERSON:Grace Liu]], she turns 30 tomorrow."),
    ("en", "Compare the iPhone 15 and the Pixel 8 cameras in a short table."),
    ("en", "The suspect, [[PERSON:Kevin Brooks]], was [[SENSITIVE:convicted of burglary in 2019]] according to the file."),
    ("en", "Please anonymise: [[PERSON:Tom Baker]] paid [[AMOUNT:£1,250.00]] from [[FINANCIAL:GB82WEST12345698765432]] on 2 June."),
    ("en", "I'm [[PERSON:Ahmed Hassan]], my passport number is [[ID_NUMBER:533380006]]. Is it valid for travel to Canada?"),
    ("en", "Can you check the grammar: 'Me and Jack went to the store yesterday and buyed milk.'"),
    ("en", "My GitHub handle is [[ACCOUNT:@dev_sam_k]] and my site is [[NETWORK:https://samkowalczyk.dev/about]]."),
    ("en", "Explain how Luhn checks work using a made-up example like 1234 5678."),
    ("en", "The meeting with [[ORG:Acme Robotics Inc.]] about their Series B is on 21 November in [[LOCATION:Berlin]]."),
    ("en", "Send the NDA to [[PERSON:Hannah Schmidt]] at [[ORG:Siemens Healthineers]] and cc legal."),
    ("en", "I'm [[SENSITIVE:gay]] and nervous about coming out to my parents, any advice?"),
    ("en", "Write a SQL query that selects all users created after 2024-01-01 from the users table."),
    ("en", "The VIN of my car is [[ID_NUMBER:1HGCM82633A004352]] and the plate is [[ID_NUMBER:KX19 ABC]]; what's the recall status?"),
    ("en", "Use IPv6 [[NETWORK:2001:db8:85a3::8a2e:370:7334]] for the staging host in the nginx config."),
    ("en", "What's the capital of Australia and how many people live there?"),
    # --- Dutch ------------------------------------------------------------------------------------
    ("nl", "Hoi, ik ben [[PERSON:Jeroen de Vries]] en ik woon op [[ADDRESS:Keizersgracht 123, 1015 CJ Amsterdam]]. Kun je een klachtbrief schrijven?"),
    ("nl", "Mijn BSN is [[ID_NUMBER:111222333]] en mijn IBAN is [[FINANCIAL:NL91ABNA0417164300]], vul het formulier voor me in."),
    ("nl", "Stuur een herinnering naar [[PERSON:Fatima el Amrani]] via [[EMAIL:fatima.elamrani@gemeente-utrecht.nl]] over de afspraak van dinsdag."),
    ("nl", "Bel [[PERSON:Jan de Bakker]] even op [[PHONE:06 12345678]] om te vragen of de taart klaar is."),
    ("nl", "De bakker op de hoek verkoopt brood voor 2,50 euro. Schrijf een recensie."),
    ("nl", "Mijn dochter [[PERSON:Sanne]] heeft [[SENSITIVE:ADHD]] en ik zoek tips voor huiswerkbegeleiding."),
    ("nl", "Ik werk bij [[ORG:Rabobank]] als [[PERSON_ATTR:risicoanalist]] en wil een functieomschrijving laten herschrijven."),
    ("nl", "Geboren op [[DOB:3 juli 1979]] te [[LOCATION:Groningen]], vraag ik hierbij een uittreksel aan."),
    ("nl", "Factuur 2024-0193 van [[ORG:Bouwbedrijf Van Dijk B.V.]]: totaal [[AMOUNT:€ 4.812,50]] over te maken naar [[FINANCIAL:NL20INGB0001234567]]."),
    ("nl", "Kun je deze zin verbeteren: 'Wij hebben gister een vergadering gehad over het budget.'"),
    ("nl", "Mijn huisarts, [[PERSON:dokter Mulder]], zegt dat ik [[SENSITIVE:een hernia]] heb. Welke oefeningen helpen?"),
    ("nl", "Het kenteken van mijn auto is [[ID_NUMBER:GV-123-K]], hoe zie ik of de APK verlopen is?"),
    ("nl", "Ik ben lid van [[SENSITIVE:de FNV]] en wil weten wat de cao zegt over overuren."),
    ("nl", "Mijn opa [[PERSON:Kees Visser]] woont in [[LOCATION:Zwolle]] en wordt volgende week 90."),
    ("nl", "Wat is het verschil tussen een bv en een eenmanszaak voor een freelancer?"),
    ("nl", "Kun je dit verslag samenvatten: [[PERSON:Lotte Jansen]] ([[EMAIL:l.jansen@umcg.nl]]) meldt dat de patiënt [[SENSITIVE:depressieve klachten]] heeft."),
    ("nl", "Het wachtwoord voor de gedeelde mailbox is [[SECRET:Zomer2024!Kantoor]], zet dat in de overdracht."),
    ("nl", "Mijn telefoonnummer is [[PHONE:+31 6 4821 7735]] en mijn vaste lijn [[PHONE:020-5551234]]."),
    ("nl", "Schrijf een gedicht over de herfst in Amsterdam, maximaal acht regels."),
    ("nl", "Graag een afspraak voor [[PERSON:mevrouw Bakker-de Wit]], geboren [[DOB:17-09-1954]], postcode [[ADDRESS:3512 JE]]."),
    ("nl", "Ik ben [[SENSITIVE:moslim]] en vraag me af of de kantine halal opties moet aanbieden."),
    ("nl", "Bedankt [[PERSON:Pieter]], de offerte van [[AMOUNT:€ 12.000]] is akkoord."),
    ("nl", "De Rose van [[PERSON:Rose van den Berg]] is een rozenras; schrijf een plantenlabel."),
    ("nl", "Ons kantoor zit aan de [[ADDRESS:Stationsplein 45, 3013 AK Rotterdam]], voeg dat toe aan de handtekening."),
    ("nl", "Kun je een excelformule maken die het gemiddelde van kolom B berekent als kolom A 'ja' is?"),
    ("nl", "Mijn creditcard [[FINANCIAL:5500 0055 5555 5559]] is gestolen, wat moet ik doen?"),
    ("nl", "Gisteren was er een storing bij KPN in heel Nederland; schrijf een tweet namens een klant."),
    ("nl", "[[PERSON:Thijs]] zit in de gevangenis wegens [[SENSITIVE:fraude]], hoe leg ik dat uit aan de kinderen?"),
    ("nl", "Het IP-adres van de printer is [[NETWORK:10.0.0.42]]; waarom kan ik niet printen vanaf mijn laptop?"),
    ("nl", "Mijn Instagram is [[ACCOUNT:@lisa.bloemen]] en ik wil een bio van 150 tekens."),
    ("nl", "Wat betekent 'BTW verlegd' op een factuur aan een Belgisch bedrijf?"),
    # --- German -----------------------------------------------------------------------------------
    ("de", "Hallo, ich bin [[PERSON:Lukas Müller]] und wohne in der [[ADDRESS:Hauptstraße 12, 10115 Berlin]]. Bitte schreib eine Kündigung für mein Fitnessstudio."),
    ("de", "Meine IBAN lautet [[FINANCIAL:DE89370400440532013000]], Kontoinhaberin [[PERSON:Anna Schneider]]."),
    ("de", "Schreib eine E-Mail an [[PERSON:Herrn Dr. Wagner]] ([[EMAIL:k.wagner@charite.de]]) wegen meines Termins."),
    ("de", "Ich wurde am [[DOB:24.12.1990]] in [[LOCATION:München]] geboren und brauche einen Lebenslauf."),
    ("de", "Meine Telefonnummer ist [[PHONE:+49 30 901820]], ruf mich an, wenn das Paket da ist."),
    ("de", "Erkläre den Unterschied zwischen GmbH und UG in drei Sätzen."),
    ("de", "Mein Chef bei der [[ORG:Deutschen Bahn]] möchte, dass ich als [[PERSON_ATTR:Projektleiterin]] den Bericht übernehme."),
    ("de", "Der Patient [[PERSON:Herr Becker]] leidet an [[SENSITIVE:Multipler Sklerose]] und braucht einen Rollstuhl."),
    ("de", "Ich bin in der [[SENSITIVE:SPD]] aktiv und möchte eine Rede über Mietpreise schreiben."),
    ("de", "Das Passwort für den Router ist [[SECRET:Fritz!Box-7590-Gast]], schreib eine Anleitung für Gäste."),
    ("de", "Kannst du diesen Satz verbessern: 'Ich habe gestern ein Buch gelesen, das war sehr spannend.'"),
    ("de", "Die Rechnung von [[ORG:Malerbetrieb Schulz GmbH]] beträgt [[AMOUNT:2.350,00 €]]."),
    ("de", "Mein Kollege [[PERSON:Jonas Weber]] aus [[LOCATION:Hamburg]] hat morgen Geburtstag."),
    ("de", "Wie hoch ist die Zugspitze und wann ist die beste Zeit für eine Wanderung?"),
    ("de", "Mein Kennzeichen ist [[ID_NUMBER:B-MK 4721]], wie melde ich das Auto ab?"),
    ("de", "Ich bin [[SENSITIVE:jüdisch]] und suche ein Rezept für Challa zum Schabbat."),
    ("de", "Bitte formatiere diese Adresse für einen Brief: [[PERSON:Petra Hoffmann]], [[ADDRESS:Lindenallee 8, 50968 Köln]]."),
    ("de", "Unser Server [[NETWORK:172.16.5.10]] meldet seit dem Update Fehler 503."),
    # --- Mixed / structured payloads ---------------------------------------------------------------
    ("en", '{"customer": {"name": "[[PERSON:Isabella Rossi]]", "email": "[[EMAIL:isabella.rossi@libero.it]]", "phone": "[[PHONE:+39 06 6982 1234]]"}, "plan": "pro", "seats": 5, "currency": "EUR"}'),
    ("en", "user_id,full_name,email,created_at\n1042,[[PERSON:Noah Fischer]],[[EMAIL:noah.f@posteo.de]],2025-02-11\n1043,[[PERSON:Mia Laurent]],[[EMAIL:mia.laurent@orange.fr]],2025-02-12"),
    ("en", "Error in config.yaml:\n  db_url: postgres://[[SECRET:admin:S3cretPw@db.internal]]:5432/prod\n  pool_size: 20\nWhy does it fail to parse?"),
    ("en", "Debug this Python:\nAPI_KEY = \"[[SECRET:AKIAIOSFODNN7EXAMPLE]]\"\nclient = boto3.client('s3', region_name='eu-west-1')"),
    ("en", "Traceback (most recent call last):\n  File \"app.py\", line 12, in <module>\n    main()\nKeyError: 'session_id'"),
    ("en", '{"model": "gpt-4o-mini", "temperature": 0.2, "messages": [{"role": "system", "content": "You are a helpful assistant."}]}'),
    ("nl", "Naam: [[PERSON:Femke de Groot]]\nAdres: [[ADDRESS:Dorpsstraat 7\n9761 AB Eelde]]\nTel: [[PHONE:050-3091234]]\nBSN: [[ID_NUMBER:123456782]]"),
    ("de", "Name: [[PERSON:Klaus Richter]]\nGeburtsdatum: [[DOB:02.05.1971]]\nKrankenkasse: [[ORG:AOK Bayern]]\nDiagnose: [[SENSITIVE:Asthma bronchiale]]"),
    ("en", "Ticket #48213 from [[PERSON:Chloe Martin]] <[[EMAIL:chloe.martin@zoho.com]]>: 'The app crashes when I upload a PNG larger than 10 MB.'"),
    ("en", "Here's a sample record for the docs (all fake): name Jane Doe, email jane@example.com. Should I keep it?"),
    ("en", "Merge these two lists of colours: red, green, blue and cyan, magenta, yellow, black."),
    ("en", "Version 3.11.4 of Python fixes CVE-2023-24329; should we upgrade from 3.10?"),
    ("en", "Order 7781-ZX shipped on 4 October via DHL Express to warehouse B7."),
]

# Templated items widen coverage of names, places and number formats. Each template is filled
# from the pools in order (deterministic), so the set is reproducible.
TEMPLATES: list[tuple[str, str]] = [
    ("en", "Please email [[PERSON:{name}]] at [[EMAIL:{email}]] about the delayed shipment."),
    ("en", "Can you call [[PERSON:{name}]] on [[PHONE:{phone}]] and confirm Thursday?"),
    ("en", "Write a reference letter for [[PERSON:{name}]], who worked with us at [[ORG:{org}]] for three years."),
    ("en", "My landlord [[PERSON:{name}]] wants the rent sent to [[FINANCIAL:{iban}]] by the first of the month."),
    ("nl", "Kun je [[PERSON:{name}]] een bedankmail sturen op [[EMAIL:{email}]]?"),
    ("nl", "[[PERSON:{name}]] woont in [[LOCATION:{city}]] en werkt bij [[ORG:{org}]]."),
    ("nl", "Bel [[PERSON:{name}]] terug op [[PHONE:{phone}]], het gaat over de offerte."),
    ("de", "Bitte schick [[PERSON:{name}]] die Unterlagen an [[EMAIL:{email}]]."),
    ("de", "[[PERSON:{name}]] aus [[LOCATION:{city}]] hat sich bei [[ORG:{org}]] beworben."),
    ("de", "Überweise das Geld an [[FINANCIAL:{iban}]], Empfänger [[PERSON:{name}]]."),
]

POOL = {
    "name": [
        "Anouk Smit", "Bram van Leeuwen", "Charlotte Dubois", "Dimitri Papadopoulos", "Eva Novak",
        "Finn Andersen", "Giulia Bianchi", "Hugo Martens", "Ingrid Larsen", "Joost Hendriks",
        "Katarzyna Wójcik", "Lars Peeters", "Marie-Claire Fontaine", "Niels Bos", "Olga Ivanova",
        "Pablo García", "Quinten de Jong", "Rania Haddad", "Sofie Claes", "Tobias Krüger",
        "Ursula Brandt", "Vincent Leclerc", "Wouter Kuipers", "Ximena Torres", "Yusuf Demir",
        "Zoë van der Meer", "Achmed Bouzid", "Birgit Lang", "Cor Willems", "Daan Mertens",
    ],
    "email": [
        "anouk.smit@ziggo.nl", "bram.vl@kpnmail.nl", "c.dubois@laposte.net", "dimitri.p@otenet.gr",
        "eva.novak@seznam.cz", "finn.andersen@mail.dk", "giulia.bianchi@tiscali.it", "hugo@martens.be",
        "ingrid.larsen@online.no", "joost.hendriks@xs4all.nl", "k.wojcik@wp.pl", "lars.peeters@telenet.be",
        "mc.fontaine@free.fr", "niels.bos@hotmail.com", "olga.ivanova@gmx.at",
    ],
    "phone": [
        "+31 6 2345 6789", "+32 470 12 34 56", "06-87654321", "+49 151 23456789", "+33 6 12 34 56 78",
        "+44 7700 900123", "010-4123456", "+31 20 624 1111", "+49 89 12345678", "0612398745",
    ],
    "org": [
        "Philips", "ASML", "Heineken", "Bol.com", "Coolblue", "Bosch", "Allianz", "Zalando",
        "Adyen", "Booking.com", "Lidl", "Ahold Delhaize",
    ],
    "city": [
        "Utrecht", "Eindhoven", "Leiden", "Maastricht", "Nijmegen", "Frankfurt", "Leipzig",
        "Düsseldorf", "Antwerpen", "Gent",
    ],
    "iban": [
        "NL91ABNA0417164300", "DE89370400440532013000", "NL20INGB0001234567", "BE68539007547034",
        "FR1420041010050500013M02606", "DE75512108001245126199",
    ],
}


def expand() -> list[tuple[str, str]]:
    out = []
    counters = {k: 0 for k in POOL}
    for _ in range(10):
        for lang, template in TEMPLATES:
            fill = {}
            for key in POOL:
                if "{" + key + "}" in template:
                    pool = POOL[key]
                    fill[key] = pool[counters[key] % len(pool)]
                    counters[key] += 1
            out.append((lang, template.format(**fill)))
    return out

LABELS = None


def load_labels() -> set[str]:
    with open(HERE / "labels.toml", "rb") as f:
        table = tomllib.load(f)
    return set(table["source"]["handmade"])


def build(index: int, lang: str, marked: str) -> dict:
    text = []
    spans = []
    at = 0  # bytes written so far
    last = 0
    for m in MARK.finditer(marked):
        before = marked[last : m.start()]
        text.append(before)
        at += len(before.encode())
        label, value = m.group(1), m.group(2)
        if label not in LABELS:
            raise SystemExit(f"item {index}: unknown label {label}")
        if value != value.strip():
            raise SystemExit(f"item {index}: span {value!r} has outer whitespace")
        start = at
        text.append(value)
        at += len(value.encode())
        spans.append({"start": start, "end": at, "label": label})
        last = m.end()
    text.append(marked[last:])
    out = "".join(text)
    if "[[" in out or "]]" in out:
        raise SystemExit(f"item {index}: unbalanced mark")
    raw = out.encode()
    for s in spans:  # the offsets must slice back to the marked value
        raw[s["start"] : s["end"]].decode()
    return {"id": f"handmade-{index:03d}", "source": "handmade", "lang": lang, "text": out, "spans": spans}


def main() -> None:
    global LABELS
    LABELS = load_labels()
    items = ITEMS + expand()
    records = [build(i, lang, marked) for i, (lang, marked) in enumerate(items)]
    with open(HERE / "handmade.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    gold = sum(len(r["spans"]) for r in records)
    negatives = sum(1 for r in records if not r["spans"])
    print(f"{len(records)} items, {gold} gold spans, {negatives} items without PII", file=sys.stderr)


if __name__ == "__main__":
    main()
