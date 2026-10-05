"""树形输出"""
from utils.helpers import format_row


def print_tree(db_name, dump_data):
    print("\n" + "=" * 60)
    print("📊 数据库结构及数据全览")
    print("=" * 60)
    print(f"📁 数据库: {db_name} ==(database)==")
    print("│")

    tables = list(dump_data.keys())
    for ti, table in enumerate(tables):
        last_t = (ti == len(tables) - 1)
        tpref = "└─── " if last_t else "├─── "
        ind = "    " if last_t else "│   "

        d = dump_data[table]
        cols = d["columns"]
        types = d.get("types", [])
        rows = d["rows"]

        print(f"{tpref}📋 表: {table} ==(table)==")
        print(f"{ind}│")
        print(f"{ind}├─── 🏷️ 列结构 (Schema) ──────────────────────────────")
        for ci, col in enumerate(cols):
            t = types[ci] if ci < len(types) else "UNKNOWN"
            last_c = (ci == len(cols) - 1)
            cpref = "    " if last_c else "│   "
            mark = "🔑 主键 (PK)" if col.lower() == "id" else "🔹"
            print(f"{ind}│   {cpref}├── {col:<15} ({t:<12}) {mark}")
        print(f"{ind}│")
        print(f"{ind}└─── 📊 数据行 (Rows) ────────────────────────────────")
        if not rows:
            print(f"{ind}     └── (空表)")
        else:
            for ri, row in enumerate(rows):
                last_r = (ri == len(rows) - 1)
                rpref = "└── " if last_r else "├── "
                print(f"{ind}     {rpref}{format_row(row)}")
        print(f"{ind}│")
    print("=" * 60)