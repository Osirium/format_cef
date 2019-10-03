import csv
import functools
import operator
import re
import sys

import camelot
import pandas as pd

url = (
    "https://web.archive.org/web/20191001144632if_/"
    "https://community.microfocus.com/dcvta86296/attachments/dcvta86296/"
    "connector-documentation/1197/2/CommonEventFormatV25.pdf"
)

CEF_KEY_NAME = "CEF Key Name"
FULL_NAME = "Full Name"
DATA_TYPE = "Data Type"
LENGTH = "Length"
MEANING = "Meaning"

drop_all_whitespace_cols = [CEF_KEY_NAME, FULL_NAME, LENGTH]
cef_fieldnames = (CEF_KEY_NAME, FULL_NAME, DATA_TYPE, LENGTH, MEANING)


def map_optional(fn, v):
    return None if v is None else fn(v)


def process(camelot_tables):
    def concat_ophans_and_widows(acc, v):
        v_head, *v_tail = v
        v_head_meaning = v_head[MEANING]

        # the next table starts with a widow
        if v_head_meaning.strip() and not v_head[CEF_KEY_NAME].strip():
            *acc_init, acc_orphan = acc
            return (
                acc_init
                + [{**acc_orphan, MEANING: acc_orphan[MEANING] + " " + v_head_meaning}]
                + v_tail
            )
        return acc + v

    return sorted(
        (
            {
                FULL_NAME: record[FULL_NAME],
                CEF_KEY_NAME: record[CEF_KEY_NAME],
                LENGTH: (
                    65535
                    if re.match(
                        r"\A.*numbers are( between)? 0 (?(1)and|to) 65535.\Z",
                        record[MEANING],
                    )
                    else map_optional(int, record[LENGTH] or None)
                ),
                DATA_TYPE: record[DATA_TYPE],
            }
            for record in functools.reduce(
                concat_ophans_and_widows,
                (
                    df_with_cols.replace(
                        {r"(\A\s+|\s+\Z)": "", r"\s+": " "}, regex=True
                    )
                    .replace(
                        {col: {r" ": ""} for col in drop_all_whitespace_cols},
                        regex=True,
                    )
                    .replace(
                        {
                            DATA_TYPE: {
                                "TimeStamp": "Time Stamp",
                                "Double": "Floating Point",
                                "Long": "Integer",
                                "MAC address": "MAC Address",
                                "Stirng": "String",
                            }
                        }
                    )
                    .to_dict(orient="records")
                    for table in camelot_tables
                    for df in (table.df,)
                    for df_with_cols in (
                        df.rename(columns=df.iloc[0]).drop(df.index[0]),
                    )
                    if tuple(df_with_cols.columns) == cef_fieldnames
                ),
            )
        ),
        key=lambda x: x[FULL_NAME].lower(),
    )


def main():
    valid_extensions = process(camelot.read_pdf(url, pages="0-end"))
    writer = csv.DictWriter(
        f=sys.stdout, fieldnames=valid_extensions[0].keys(), lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(valid_extensions)


if __name__ == "__main__":
    main()
