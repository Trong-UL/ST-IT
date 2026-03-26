import pandas as pd

def parse_procmon_csv(path: str):
    df = pd.read_csv(path)
    if "Time" in df.columns:
        df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    summary = {
        "total_events": int(len(df)),
        "write_file": int(len(df[df["Operation"] == "WriteFile"])) if "Operation" in df.columns else 0,
        "create_ops": int(len(df[df["Operation"].str.contains("Create", na=False)])) if "Operation" in df.columns else 0,
        "reg_sets": int(len(df[df["Operation"] == "RegSetValue"])) if "Operation" in df.columns else 0,
    }
    top_paths = []
    if "Path" in df.columns:
        top_paths = df["Path"].value_counts().head(10).index.tolist()
    spawns = []
    if "Operation" in df.columns and "Process Name" in df.columns:
        spawns = df[df["Operation"] == "CreateProcess"][["Process Name","Path"]].head(50).to_dict("records")
    return df, summary, top_paths, spawns
