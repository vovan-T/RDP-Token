"""Canonical X.509 field names shared by Token UI components."""

OID_LABELS = {
    "2.5.4.3": "CN — имя сертификата",
    "2.5.4.4": "SURNAME — фамилия",
    "2.5.4.42": "GIVENNAME — имя и отчество",
    "2.5.4.6": "C — страна",
    "2.5.4.8": "ST — регион",
    "2.5.4.7": "L — город",
    "2.5.4.10": "O — организация",
    "2.5.4.11": "OU — подразделение",
    "2.5.4.12": "TITLE — должность",
    "2.5.4.9": "STREET — улица",
    "2.5.4.17": "POSTALCODE — почтовый индекс",
    "1.2.840.113549.1.9.1": "E — e-mail",
    "2.5.4.5": "SERIALNUMBER — серийный идентификатор",
    "1.2.643.3.131.1.1": "ИНН — 1.2.643.3.131.1.1",
    "1.2.643.100.3": "СНИЛС — 1.2.643.100.3",
    "1.2.643.100.1": "ОГРН — 1.2.643.100.1",
}


def name_fields(name) -> list[dict[str, str]]:
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": OID_LABELS.get(attribute.oid.dotted_string,
                                   f"OID {attribute.oid.dotted_string}"),
            "value": str(attribute.value),
        }
        for rdn in name.rdns
        for attribute in rdn
    ]
