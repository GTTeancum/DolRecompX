# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse pinned public instruction metadata; no game inputs."""
import re

class ValidationError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise ValidationError(message)

def parse_decoder_enum(text):
    match = re.search(r"typedef\s+enum\s*\{(.*?)\}\s*PPCOpcode\s*;", text, re.S)
    require(match is not None, "PPCOpcode declaration missing")
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(1), flags=re.S)
    result = []
    next_value = 0
    for field in body.split(","):
        if not field.strip():
            continue
        item = re.fullmatch(r"\s*(PPC_OP_\w+)\s*(?:=\s*(0[xX][0-9a-fA-F]+|[0-9]+))?\s*", field)
        require(item is not None, f"Unrecognized enum entry: {field!r}")
        name, explicit = item.groups()
        value = int(explicit, 0) if explicit else next_value
        require(value == len(result), "PPCOpcode values are not contiguous from zero")
        result.append((name, value))
        next_value = value + 1
    require(len(result) == 238, "Unexpected enum size")
    require(result[0] == ("PPC_OP_UNKNOWN", 0), "UNKNOWN must be enum zero")
    require(result[-1] == ("PPC_OP_COUNT", 237), "Unexpected COUNT sentinel")
    return result[:-1]

def parse_reference(text):
    """Parse pinned literal tables and reconstruct numeric-selector lookup."""
    refs = [{"id": 0, "table": "s_unknown_op_info", "opcode": 0,
             "name": "unknown_instruction", "type": "Unknown", "cycles": 0,
             "line": 34, "selector": None}]
    tables = {}
    pattern = r"constexpr std::array<GekkoOPTemplate,\s*(\d+)>\s+(s_\w+)\{\{(.*?)\}\};"
    for table_match in re.finditer(pattern, text, re.S):
        declared, table, body = table_match.groups()
        require(table in ("s_primary_table", "s_table4_2", "s_table4_3", "s_table4",
                          "s_table19", "s_table31", "s_table59", "s_table63", "s_table63_2"),
                "Unrecognized reference table: " + table)
        rows = []
        for match in re.finditer(r'\{(\d+),\s*"([^"]+)",\s*OpType::(\w+),\s*(\d+)\s*,', body):
            opcode, name, kind, cycles = match.groups()
            if table == "s_primary_table":
                selector = {"primary": int(opcode), "subopcode_bits": None, "subopcode": None}
            else:
                primary = int(re.search(r"s_table(\d+)", table).group(1))
                bits = 5 if table in ("s_table4_2", "s_table59", "s_table63_2") else 6 if table == "s_table4_3" else 10
                selector = {"primary": primary, "subopcode_bits": bits, "subopcode": int(opcode)}
            row = {"id": len(refs), "table": table, "opcode": int(opcode),
                   "name": name, "type": kind, "cycles": int(cycles),
                   "line": text.count("\n", 0, table_match.start(3) + match.start()) + 1,
                   "selector": selector}
            refs.append(row)
            rows.append(row)
        require(len(rows) == int(declared), f"Wrong entry count: {table}")
        require(table not in tables, f"Duplicate table: {table}")
        tables[table] = rows
    require(len(tables) == 9 and len(refs) == 243, "Incomplete PPCTables parse")
    primary = [0] * 64
    subtables = {p: [0] * 1024 for p in (4, 19, 31, 59, 63)}
    for row in tables["s_primary_table"]:
        require(not primary[row["opcode"]], "Primary lookup collision")
        primary[row["opcode"]] = row["id"]
    for table in ("s_table4_2", "s_table4_3", "s_table4", "s_table19", "s_table31", "s_table59", "s_table63", "s_table63_2"):
        for row in tables[table]:
            sel = row["selector"]
            bits = sel["subopcode_bits"]
            for high in range(1 << (10 - bits)):
                index = (high << bits) | sel["subopcode"]
                target = subtables[sel["primary"]]
                require(not target[index], f"Subtable lookup collision: {table}")
                target[index] = row["id"]
    lookup = [[subtables[p][x] if p in subtables else primary[p] for x in range(1024)] for p in range(64)]
    return refs, lookup
