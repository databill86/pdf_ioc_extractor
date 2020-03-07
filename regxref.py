import re
import sys

# ref: https://unicode-table.com/en/blocks/


def regex(_type):
    pattern = dict(
        address=r"(^(\d+)\s?([A-Za-z](?=\s))?\s(.*?)\s([^ ]+?)\s?((?<=\s)APT)?\s?((?<=\s)\d*)?$)",
        arabic=r"[\u0600-\u06FF]",
        archive=r"(([^\s|\W])+[a-z-A-Z0-9\-\_]+((?:\.zip)|(?:\.7z)|(?:\.rar)|(?:\.xz)|(?:\.tar)|(?:\.tar.gz)))",
        base64=r"(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$)",
        binary=r"(([^\s|\W])+[a-z-A-Z0-9\-\_]+((?:\.exe)|(?:\.msi)|(?:\.dll)|(?:\.bin)))",
        btc=r"(^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)",
        cc=r"((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])",
        chinese=r"[\u4E00-\u9FFF]",
        cyrillic=r"[\u0400-\u04FF]",
        date=r"(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}",
        office=r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+((?:\.doc)|(?:\.docx)|(?:\.xls)|(?:\.xlsx)|(?:\.pdf)))",
        domain=r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?<!fireeye)(?:\[\.\]|\.)(?![a-z-]+\.gov|gov)(?!add|asn|asp|bat|bin|cpj|dat|db|dll|doc|drv|exe|gif|gov|gz|htm|img|ini|jsp|jpg|key|lnk|log|md|msi|nat|rar|rer|rpm|out|pdf|php|png|src|sh|sys|tmp|txt|vbe|xls|xml|xpm|zip|[i\.e]$|[e\.g]$)(?:[a-z]{2,3})(?!@)\b)",
        email=r"([a-zA-Z0-9_.+-]+(\[@\]|@)(?!fireeye)[a-zA-Z0-9-.]+(\.|\[\.\])(?![a-z-]+\.gov|gov)([a-zA-Z0-9-.]{2,6}\b))",
        image=r"(([^\s|\W])+[a-z-A-Z0-9\-\_]+((?:\.jpg)|(?:\.gif)|(?:\.jpeg)|(?:\.jpg)|(?:\.png)|(?:\.svg)))",
        ipv4=r"(((?![0])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
        md5=r"[A-Fa-f0-9]{32}\b",
        phone=r"(^(?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-]))\$)",
        po_box=r"P\.? ?O\.? Box \d+",
        script=r"(([^\s])+[a-z-A-Z0-9\-\_]+((?:\.vbs)|(?:\.sh)|(?:\.bat)|(?:\.ps1)|(?:\.py)))",
        sha1=r"[A-Fa-f0-9]{40}\b",
        sha256=r"[A-Fa-f0-9]{64}\b",
        sha512=r"[A-Fa-f0-9]{128}\b",
        ssn=r"(?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}",
        url=r"((http[s]?(\[:\]|:)|hxxp[s]?(\[:\]|:)|file\[:\])\/\/((?![0])\d{1,}(\.|\[\.\])\d{1,3}(\.|\[\.\])\d{1,3}\/(?:(\.|\[\.\])(?![0])\d{1,3})|(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-zA-Z][0-9a-zA-Z]))+[a-zA-Z0-9]))",
        webfile=r"(([^\s])+[a-z-A-Z0-9\-\_]+((?:\.html)|(?:\.htm\b)|(?:\.htmls)|(?:\.jsp\b)|(?:\.js\b)|(?:\.php\b)|(?:\.asp\b)|(?:\.aspx)))",
        windir=r"^[a-zA-Z]{1}:(\\|\\\\|\/\/)(?!.*com|net|org|gov|www)[a-zA-Z0-9\-\_\\\/]+[a-zA-Z0-9\-\_]+[a-zA-Z0-9\-\_]",
        zip_code=r"\b\d{5}(?:[-\s]\d{4})?\b"
    )
    try:
        pattern = re.compile(pattern[_type])
    except re.error:
        sys.exit("[!] Invalid regex specified.")

    return pattern
