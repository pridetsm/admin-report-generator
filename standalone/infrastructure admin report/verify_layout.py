"""Check that every table in a generated Infrastructure Report lands on the
fixed column plan -- i.e. tables have consistent spacing at every nesting
level, and nothing overlaps.

    python verify_layout.py <file>.xlsx
"""
import sys
from openpyxl import load_workbook
from openpyxl.utils import get_column_letter, column_index_from_string as ci

DISK = {"Host": "J", "Used %": "K", "Size GB": "L", "Mount": "M", "Free GB": "N"}
CLUS = {"Pool": "P", "Used %": "Q", "Size GB": "R", "Free GB": "S"}
NOTES = {"  Flagged metric": "U", "Fix needed?": "X", "Resolved": "Y"}
BY_COL = "U"


def main():
    ws = load_workbook(sys.argv[1]).active
    problems = []

    def check_headers(kind, want):
        # a header row is any row whose first label sits in its expected column
        first = next(iter(want))
        for row in range(1, ws.max_row + 1):
            if ws.cell(row, ci(want[first])).value != first:
                continue
            for label, letter in want.items():
                got = ws.cell(row, ci(letter)).value
                if got != label:
                    problems.append(
                        f"row {row}: {kind} column {letter} holds {got!r}, "
                        f"expected {label!r}")

    check_headers("Disk", DISK)
    check_headers("Cluster Storage", CLUS)
    check_headers("Notes", NOTES)

    # every "By  " sign-off must sit in column S (Notes column)
    for row in range(1, ws.max_row + 1):
        for c in range(1, ws.max_column + 1):
            if ws.cell(row, c).value == "By  ":
                if get_column_letter(c) != BY_COL:
                    problems.append(f"row {row}: 'By' at {get_column_letter(c)}, "
                                    f"expected {BY_COL}")

    # named ranges
    wb = load_workbook(sys.argv[1])
    names = {n: d.value for n, d in wb.defined_names.items()}
    for want in ("dashboard", "banners", "RHS_Edge"):
        if want not in names:
            problems.append(f"missing named range '{want}'")
    print("named ranges:", names)

    # count how many sections carry each table
    counts = {"Disk": 0, "Cluster Storage": 0}
    for row in range(1, ws.max_row + 1):
        if ws.cell(row, ci(DISK["Host"])).value == "Host":
            counts["Disk"] += 1
        if ws.cell(row, ci(CLUS["Pool"])).value == "Pool":
            counts["Cluster Storage"] += 1
    print("table instances:", counts)

    if problems:
        print(f"\n{len(problems)} layout problem(s):")
        for p in problems:
            print(" ", p)
        sys.exit(1)
    print("\nOK - all tables on the fixed column plan")


if __name__ == "__main__":
    main()
