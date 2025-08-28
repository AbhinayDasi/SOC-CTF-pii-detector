import sys
import csv
import json
import re

# ----------------------------
# Regex patterns for standalone PII
# ----------------------------
PHONE_PATTERN = re.compile(r"^\d{10}$")
AADHAR_PATTERN = re.compile(r"^\d{12}$")
PASSPORT_PATTERN = re.compile(r"^[A-Z][0-9]{7}$", re.IGNORECASE)
UPI_PATTERN = re.compile(r"^[\w\.\-]+@[a-z]{2,}$")

# ----------------------------
# Masking helpers
# ----------------------------
def mask_phone(value):
    return value[:2] + "XXXXXX" + value[-2:]

def mask_aadhar(value):
    return value[:4] + " XXXX XXXX " + value[-4:]

def mask_passport(value):
    return value[0] + "XXXXXXX"

def mask_upi(value):
    return value[:2] + "XXX@upi"

def mask_name(value):
    parts = value.split()
    masked = []
    for p in parts:
        if len(p) > 1:
            masked.append(p[0] + "XXX")
        else:
            masked.append(p)
    return " ".join(masked)

def mask_email(value):
    try:
        user, domain = value.split("@")
        return user[:2] + "XXX@" + domain
    except:
        return "[REDACTED_EMAIL]"

def mask_address(value):
    return "[REDACTED_ADDRESS]"

def mask_ip(value):
    return "[REDACTED_IP]"

# ----------------------------
# Detect and redact PII in one record
# ----------------------------
def process_record(record):
    is_pii = False
    redacted = {}

    # Track combinatorial PII fields
    combo_flags = {
        "name": False,
        "email": False,
        "address": False,
        "ip_address": False
    }

    for key, val in record.items():
        if not isinstance(val, str):
            redacted[key] = val
            continue

        # --- Standalone PII ---
        if key == "phone" and PHONE_PATTERN.match(val):
            redacted[key] = mask_phone(val)
            is_pii = True
        elif key == "aadhar" and AADHAR_PATTERN.match(val):
            redacted[key] = mask_aadhar(val)
            is_pii = True
        elif key == "passport" and PASSPORT_PATTERN.match(val):
            redacted[key] = mask_passport(val)
            is_pii = True
        elif key == "upi_id" and UPI_PATTERN.match(val):
            redacted[key] = mask_upi(val)
            is_pii = True

        # --- Combinatorial candidates ---
        elif key == "name" and len(val.split()) >= 2:
            combo_flags["name"] = True
            redacted[key] = mask_name(val)
        elif key == "email" and "@" in val:
            combo_flags["email"] = True
            redacted[key] = mask_email(val)
        elif key == "address":
            combo_flags["address"] = True
            redacted[key] = mask_address(val)
        elif key == "ip_address":
            combo_flags["ip_address"] = True
            redacted[key] = mask_ip(val)
        else:
            redacted[key] = val

    # If at least 2 combinatorial fields → mark as PII
    if sum(1 for v in combo_flags.values() if v) >= 2:
        is_pii = True
    else:
        # Roll back masking if not enough fields
        for k, flagged in combo_flags.items():
            if flagged:
                redacted[k] = record[k]

    return redacted, is_pii

# ----------------------------
# Main program
# ----------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python detector_abhinay_dasi.py iscp_pii_dataset_-_Sheet1.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "redacted_output_abhinay_dasi.csv"

    with open(input_file, "r", newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        header = next(reader)

        # Ensure header matches expected format
        if header[0].lower().startswith("record_id"):
            fieldnames = ["record_id", "redacted_data_json", "is_pii"]
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                if len(row) < 2:
                    continue
                record_id = row[0]
                try:
                    data = json.loads(row[1])
                except:
                    data = {}

                redacted, pii_flag = process_record(data)

                writer.writerow({
                    "record_id": record_id,
                    "redacted_data_json": json.dumps(redacted),
                    "is_pii": str(pii_flag)
                })

if __name__ == "__main__":
    main()
