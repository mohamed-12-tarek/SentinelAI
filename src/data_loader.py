from pathlib import Path
import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"

if not RAW_DIR.exists():
    RAW_DIR = PROJECT_ROOT / "data"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
TEMP_DIR = PROCESSED_DIR / "duckdb_temp"
COMBINED_PATH = PROCESSED_DIR / "combined_shuffled.parquet"
SAMPLE_PATH = PROCESSED_DIR / "eda_sample.parquet"
MEMORY_LIMIT = "8GB"
THREADS = 4
SAMPLE_FRACTION = 0.10
RANDOM_SEED = 42


def quote_identifier(name):
    return '"' + name.replace('"', '""') + '"'


def quote_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def get_connection():

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    connection = duckdb.connect()

    connection.execute(
        f"SET memory_limit = '{MEMORY_LIMIT}'"
    )

    connection.execute(
        f"SET temp_directory = {quote_string(TEMP_DIR.as_posix())}"
    )

    connection.execute(
        f"SET threads = {THREADS}"
    )

    return connection


def get_csv_files():

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in: {RAW_DIR}"
        )

    return csv_files


def build_file_query(connection, file):

    file_path = file.resolve().as_posix()
    file_path_sql = quote_string(file_path)

    source_name = quote_string(file.name)

    relation = f"""
        read_csv(
            {file_path_sql},
            sample_size = -1,
            union_by_name = true
        )
    """

    columns_info = connection.execute(
        f"DESCRIBE SELECT * FROM {relation}"
    ).fetchall()

    column_names = [
        row[0] for row in columns_info
    ]

    cleaned_names = [
        name.strip() for name in column_names
    ]

    if len(cleaned_names) != len(set(cleaned_names)):
        raise ValueError(
            f"Duplicate column names after cleaning in {file.name}"
        )

    if not any(name.casefold() == "label" for name in cleaned_names):
        raise ValueError(
            f"Label column not found in {file.name}"
        )

    select_columns = []

    for original_name, cleaned_name in zip(
        column_names,
        cleaned_names
    ):

        original_identifier = quote_identifier(original_name)
        cleaned_identifier = quote_identifier(cleaned_name)

        if cleaned_name.casefold() == "label":

            expression = f"""
                TRIM(CAST(
                    {original_identifier} AS VARCHAR
                )) AS {cleaned_identifier}
            """

        else:

            expression = (
                f"{original_identifier} AS {cleaned_identifier}"
            )

        select_columns.append(expression)

    select_columns.append(
        f"{source_name} AS {quote_identifier('Source_File')}"
    )

    return f"""
        SELECT
            {', '.join(select_columns)}
        FROM {relation}
    """


def build_combined_dataset():
    csv_files = get_csv_files()
    connection = get_connection()

    try:
        print("Files Found:", len(csv_files))

        for file in csv_files:
            print("Reading:", file.name)

        queries = [
            build_file_query(connection, file)
            for file in csv_files
        ]

        union_query = " UNION ALL BY NAME ".join(queries)
        output_path = quote_string(
            COMBINED_PATH.resolve().as_posix()
        )

        if COMBINED_PATH.exists():
            COMBINED_PATH.unlink()

        print("\nCombining and shuffling datasets...")

        connection.execute(f"""
            COPY (
                SELECT *
                FROM ({union_query})
                ORDER BY random()
            )
            TO {output_path}
            (
                FORMAT PARQUET,
                COMPRESSION ZSTD
            )
        """)

        total_rows = connection.execute(f"""
            SELECT COUNT(*)
            FROM read_parquet({output_path})
        """).fetchone()[0]

        total_columns = connection.execute(f"""
            SELECT COUNT(*)
            FROM (
                DESCRIBE
                SELECT *
                FROM read_parquet({output_path})
            )
        """).fetchone()[0]

        print("\nCombined Dataset Created Successfully")

        return {
            "files": len(csv_files),
            "rows": total_rows,
            "columns": total_columns,
            "output": str(COMBINED_PATH)
        }

    finally:
        connection.close()



def create_stratified_sample(
    sample_fraction=SAMPLE_FRACTION,
    random_seed=RANDOM_SEED
):

    if not 0 < sample_fraction <= 1:
        raise ValueError(
            "sample_fraction must be between 0 and 1"
        )

    if not COMBINED_PATH.exists():
        raise FileNotFoundError(
            "Combined dataset does not exist. "
            "Run build_combined_dataset first."
        )

    connection = get_connection()

    try:

        input_path = quote_string(
            COMBINED_PATH.resolve().as_posix()
        )

        output_path = quote_string(
            SAMPLE_PATH.resolve().as_posix()
        )

        connection.execute(
            f"SELECT setseed({random_seed / 100})"
        )

        if SAMPLE_PATH.exists():
            SAMPLE_PATH.unlink()

        print("\nCreating Stratified Sample...")

        connection.execute(f"""
            COPY (

                WITH scored AS MATERIALIZED (
                    SELECT
                        *,
                        random() AS sample_key

                    FROM read_parquet({input_path})
                ),

                ranked AS (
                    SELECT
                        *,

                        ROW_NUMBER() OVER (
                            PARTITION BY "Label"
                            ORDER BY sample_key
                        ) AS row_num,

                        COUNT(*) OVER (
                            PARTITION BY "Label"
                        ) AS class_count

                    FROM scored
                )

                SELECT * EXCLUDE (
                    sample_key,
                    row_num,
                    class_count
                )

                FROM ranked

                WHERE row_num <= GREATEST(
                    1,
                    CAST(
                        CEIL(
                            class_count * {sample_fraction}
                        ) AS BIGINT
                    )
                )

                ORDER BY random()

            )

            TO {output_path}
            (
                FORMAT PARQUET,
                COMPRESSION ZSTD
            )
        """)

        sample_rows = connection.execute(f"""
            SELECT COUNT(*)
            FROM read_parquet({output_path})
        """).fetchone()[0]

        print("\nStratified Sample Created Successfully")

        return {
            "sample_rows": sample_rows,
            "sample_fraction": sample_fraction,
            "output": str(SAMPLE_PATH)
        }

    finally:
        connection.close()



def get_dataset_summary():

    if not COMBINED_PATH.exists():
        raise FileNotFoundError(
            "Combined dataset does not exist."
        )

    connection = get_connection()

    try:

        input_path = quote_string(
            COMBINED_PATH.resolve().as_posix()
        )

        total_rows = connection.execute(f"""
            SELECT COUNT(*)
            FROM read_parquet({input_path})
        """).fetchone()[0]

        label_distribution = connection.execute(f"""
            SELECT
                "Label",
                COUNT(*) AS Records,

                ROUND(
                    COUNT(*) * 100.0 /
                    SUM(COUNT(*)) OVER (),
                    2
                ) AS Percentage

            FROM read_parquet({input_path})

            GROUP BY "Label"

            ORDER BY Records DESC
        """).df()

        source_distribution = connection.execute(f"""
            SELECT
                "Source_File",
                COUNT(*) AS Records

            FROM read_parquet({input_path})

            GROUP BY "Source_File"

            ORDER BY "Source_File"
        """).df()

        return {
            "total_rows": total_rows,
            "label_distribution": label_distribution,
            "source_distribution": source_distribution
        }

    finally:
        connection.close()


if __name__ == "__main__":

    print("=" * 50)
    print("SENTINELAI DATA LOADER")
    print("=" * 50)

    print("\nStep 1: Building Combined Dataset")

    combined_result = build_combined_dataset()

    print(combined_result)

    print("\nStep 2: Creating Stratified Sample")

    sample_result = create_stratified_sample(
        sample_fraction=0.10,
        random_seed=42
    )

    print(sample_result)

    print("\nStep 3: Dataset Summary")

    summary = get_dataset_summary()

    print("\nTotal Records:")
    print(summary["total_rows"])

    print("\nLabel Distribution:")
    print(summary["label_distribution"])

    print("\nSource Distribution:")
    print(summary["source_distribution"])

    print("\nAll Operations Completed Successfully")
